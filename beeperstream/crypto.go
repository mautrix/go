// Copyright (c) 2026 Batuhan İçöz
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package beeperstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"go.mau.fi/util/jsonbytes"
	"go.mau.fi/util/random"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type innerPayload struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

func makeStreamKey() jsonbytes.UnpaddedBytes {
	return random.Bytes(32)
}

func newStreamGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid stream key length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func deriveStreamID(key []byte, roomID id.RoomID, eventID id.EventID) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(roomID))
	mac.Write([]byte(eventID))
	return base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
}

func encryptLogicalEvent(logicalType event.Type, payload json.RawMessage, roomID id.RoomID, eventID id.EventID, key []byte) (*event.Content, error) {
	if roomID == "" || eventID == "" {
		return nil, fmt.Errorf("missing beeper stream identifiers")
	}
	gcm, err := newStreamGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(innerPayload{
		Type:    logicalType.Type,
		Content: payload,
	})
	if err != nil {
		return nil, err
	}
	iv := random.Bytes(gcm.NonceSize())
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	return &event.Content{
		Parsed: &event.EncryptedEventContent{
			Algorithm:        id.AlgorithmBeeperStreamV1,
			StreamID:         deriveStreamID(key, roomID, eventID),
			IV:               iv,
			MegolmCiphertext: ciphertext,
		},
	}, nil
}

func decryptLogicalEvent(content *event.Content, key []byte) (event.Type, json.RawMessage, error) {
	gcm, err := newStreamGCM(key)
	if err != nil {
		return event.Type{}, nil, err
	}
	encrypted := content.AsEncrypted()
	if encrypted.Algorithm == "" && content != nil && content.Parsed == nil && len(content.VeryRaw) > 0 {
		if err = content.ParseRaw(event.ToDeviceEncrypted); err != nil {
			return event.Type{}, nil, err
		}
		encrypted = content.AsEncrypted()
	}
	if len(encrypted.IV) != gcm.NonceSize() {
		return event.Type{}, nil, fmt.Errorf("invalid beeper stream IV length %d", len(encrypted.IV))
	}
	plaintext, err := gcm.Open(nil, encrypted.IV, encrypted.MegolmCiphertext, nil)
	if err != nil {
		return event.Type{}, nil, err
	}
	var payload innerPayload
	if err = json.Unmarshal(plaintext, &payload); err != nil {
		return event.Type{}, nil, err
	}
	switch payload.Type {
	case event.ToDeviceBeeperStreamSubscribe.Type:
		return event.ToDeviceBeeperStreamSubscribe, payload.Content, nil
	case event.ToDeviceBeeperStreamUpdate.Type:
		return event.ToDeviceBeeperStreamUpdate, payload.Content, nil
	default:
		return event.Type{}, nil, fmt.Errorf("unknown beeper stream event type %q", payload.Type)
	}
}
