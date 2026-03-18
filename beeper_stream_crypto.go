// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"

	"go.mau.fi/util/random"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type beeperStreamEncryptedPayload struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

func makeStreamKey() string {
	return base64.RawStdEncoding.EncodeToString(random.Bytes(32))
}

func makeStreamID() id.StreamID {
	return id.StreamID(base64.RawStdEncoding.EncodeToString(random.Bytes(16)))
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

func encryptPayload(logicalType event.Type, payload *event.Content, streamID id.StreamID, gcm cipher.AEAD) (*event.EncryptedEventContent, error) {
	plaintextContent, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(beeperStreamEncryptedPayload{
		Type:    logicalType.Type,
		Content: plaintextContent,
	})
	if err != nil {
		return nil, err
	}
	iv := random.Bytes(gcm.NonceSize())
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	return &event.EncryptedEventContent{
		Algorithm:        id.AlgorithmBeeperStreamAESGCM,
		IV:               base64.RawStdEncoding.EncodeToString(iv),
		StreamID:         streamID,
		StreamCiphertext: base64.RawStdEncoding.AppendEncode(nil, ciphertext),
	}, nil
}

func encryptBeeperStreamEvent(logicalType event.Type, content *event.Content, streamID id.StreamID, base64Key string) (*event.EncryptedEventContent, error) {
	gcm, err := newStreamGCM(base64Key)
	if err != nil {
		return nil, err
	}
	return encryptPayload(logicalType, content, streamID, gcm)
}

func decryptPayload(content *event.EncryptedEventContent, gcm cipher.AEAD) (*beeperStreamEncryptedPayload, error) {
	iv, err := base64.RawStdEncoding.DecodeString(content.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode beeper stream IV: %w", err)
	} else if len(iv) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid beeper stream IV length %d", len(iv))
	}
	ciphertext, err := base64.RawStdEncoding.AppendDecode(nil, content.StreamCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode beeper stream ciphertext: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	var payload beeperStreamEncryptedPayload
	if err = json.Unmarshal(plaintext, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func decryptEvent(content *event.EncryptedEventContent, base64Key string) (event.Type, *event.Content, error) {
	gcm, err := newStreamGCM(base64Key)
	if err != nil {
		return event.Type{}, nil, err
	}
	payload, err := decryptPayload(content, gcm)
	if err != nil {
		return event.Type{}, nil, err
	}
	logicalType := event.Type{Type: payload.Type, Class: event.ToDeviceEventType}
	switch payload.Type {
	case event.ToDeviceBeeperStreamSubscribe.Type:
		logicalType = event.ToDeviceBeeperStreamSubscribe
	case event.ToDeviceBeeperStreamUpdate.Type:
		logicalType = event.ToDeviceBeeperStreamUpdate
	}
	var parsed event.Content
	if err = json.Unmarshal(payload.Content, &parsed); err != nil {
		return event.Type{}, nil, err
	}
	if err = parsed.ParseRaw(logicalType); err != nil {
		return event.Type{}, nil, err
	}
	return logicalType, &parsed, nil
}

func newUpdateContent(roomID id.RoomID, eventID id.EventID, content map[string]any) (*event.Content, error) {
	if roomID == "" || eventID == "" {
		return nil, fmt.Errorf("missing beeper stream identifiers")
	}
	if _, ok := content["room_id"]; ok {
		return nil, fmt.Errorf("beeper stream payload may not override room_id")
	} else if _, ok := content["event_id"]; ok {
		return nil, fmt.Errorf("beeper stream payload may not override event_id")
	}
	raw := maps.Clone(content)
	if raw == nil {
		raw = make(map[string]any, 2)
	}
	raw["room_id"] = roomID
	raw["event_id"] = eventID
	return &event.Content{Raw: raw}, nil
}
