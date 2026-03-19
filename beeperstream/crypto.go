// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package beeperstream

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"go.mau.fi/util/random"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type innerPayload struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

func makeStreamKey() string {
	return base64.RawStdEncoding.EncodeToString(random.Bytes(32))
}

func newStreamGCM(base64Key string) (cipher.AEAD, error) {
	key, err := base64.RawStdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode stream key: %w", err)
	} else if len(key) != 32 {
		return nil, fmt.Errorf("invalid stream key length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encryptLogicalEvent(logicalType event.Type, payload json.RawMessage, roomID id.RoomID, eventID id.EventID, base64Key string) (*event.BeeperStreamEncryptedEventContent, error) {
	if roomID == "" || eventID == "" {
		return nil, fmt.Errorf("missing beeper stream identifiers")
	}
	gcm, err := newStreamGCM(base64Key)
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
	return &event.BeeperStreamEncryptedEventContent{
		RoomID:     roomID,
		EventID:    eventID,
		Algorithm:  id.AlgorithmBeeperStreamAESGCM,
		IV:         base64.RawStdEncoding.EncodeToString(iv),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decryptLogicalEvent(content *event.BeeperStreamEncryptedEventContent, base64Key string) (event.Type, json.RawMessage, error) {
	gcm, err := newStreamGCM(base64Key)
	if err != nil {
		return event.Type{}, nil, err
	}
	iv, err := base64.RawStdEncoding.DecodeString(content.IV)
	if err != nil {
		return event.Type{}, nil, fmt.Errorf("failed to decode beeper stream IV: %w", err)
	} else if len(iv) != gcm.NonceSize() {
		return event.Type{}, nil, fmt.Errorf("invalid beeper stream IV length %d", len(iv))
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(content.Ciphertext)
	if err != nil {
		return event.Type{}, nil, fmt.Errorf("failed to decode beeper stream ciphertext: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return event.Type{}, nil, err
	}
	var payload innerPayload
	if err = json.Unmarshal(plaintext, &payload); err != nil {
		return event.Type{}, nil, err
	}
	logicalType := event.Type{Type: payload.Type, Class: event.ToDeviceEventType}
	switch payload.Type {
	case event.ToDeviceBeeperStreamSubscribe.Type:
		logicalType = event.ToDeviceBeeperStreamSubscribe
	case event.ToDeviceBeeperStreamUpdate.Type:
		logicalType = event.ToDeviceBeeperStreamUpdate
	}
	return logicalType, payload.Content, nil
}
