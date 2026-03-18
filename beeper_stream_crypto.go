// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/rs/zerolog"
	"go.mau.fi/util/random"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type beeperStreamInnerPayload struct {
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

func encryptLogicalEvent(logicalType event.Type, content *event.Content, roomID id.RoomID, eventID id.EventID, base64Key string) (*event.BeeperStreamEncryptedEventContent, error) {
	if roomID == "" || eventID == "" {
		return nil, fmt.Errorf("missing beeper stream identifiers")
	}
	gcm, err := newStreamGCM(base64Key)
	if err != nil {
		return nil, err
	}
	plaintextContent, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(beeperStreamInnerPayload{
		Type:    logicalType.Type,
		Content: plaintextContent,
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

func decryptLogicalEvent(content *event.BeeperStreamEncryptedEventContent, base64Key string) (event.Type, *event.Content, error) {
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
	var payload beeperStreamInnerPayload
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

	var raw map[string]any
	if err = json.Unmarshal(payload.Content, &raw); err != nil {
		return event.Type{}, nil, err
	}
	if raw == nil {
		raw = make(map[string]any)
	}
	raw["room_id"] = content.RoomID
	raw["event_id"] = content.EventID

	veryRaw, err := json.Marshal(raw)
	if err != nil {
		return event.Type{}, nil, err
	}
	parsed := &event.Content{VeryRaw: veryRaw, Raw: maps.Clone(raw)}
	if err = parsed.ParseRaw(logicalType); err != nil {
		return event.Type{}, nil, err
	}
	return logicalType, parsed, nil
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
	veryRaw, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	return &event.Content{VeryRaw: veryRaw, Raw: raw}, nil
}

func stripUpdateRouting(content *event.Content) (*event.Content, error) {
	if content == nil {
		return &event.Content{Raw: map[string]any{}}, nil
	}
	raw := maps.Clone(content.Raw)
	if raw == nil {
		veryRaw, err := json.Marshal(content)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(veryRaw, &raw); err != nil {
			return nil, err
		}
	}
	delete(raw, "room_id")
	delete(raw, "event_id")
	veryRaw, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	return &event.Content{VeryRaw: veryRaw, Raw: raw}, nil
}

func stripSubscribeRouting(deviceID id.DeviceID, expiryMS int64) (*event.Content, error) {
	raw := map[string]any{
		"device_id": deviceID,
		"expiry_ms": expiryMS,
	}
	veryRaw, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	return &event.Content{VeryRaw: veryRaw, Raw: raw}, nil
}

func maybeEncryptLogicalEvent(logicalType event.Type, content *event.Content, descriptor *event.BeeperStreamInfo) (event.Type, *event.Content, error) {
	if descriptor == nil || descriptor.Encryption == nil {
		return logicalType, content, nil
	}
	switch logicalType {
	case event.ToDeviceBeeperStreamSubscribe:
		subscribe := content.AsBeeperStreamSubscribe()
		payload, err := stripSubscribeRouting(subscribe.DeviceID, subscribe.ExpiryMS)
		if err != nil {
			return event.Type{}, nil, err
		}
		encrypted, err := encryptLogicalEvent(logicalType, payload, subscribe.RoomID, subscribe.EventID, descriptor.Encryption.Key)
		if err != nil {
			return event.Type{}, nil, err
		}
		return event.ToDeviceBeeperStreamEncrypted, &event.Content{Parsed: encrypted}, nil
	case event.ToDeviceBeeperStreamUpdate:
		update := content.AsBeeperStreamUpdate()
		payload, err := stripUpdateRouting(content)
		if err != nil {
			return event.Type{}, nil, err
		}
		encrypted, err := encryptLogicalEvent(logicalType, payload, update.RoomID, update.EventID, descriptor.Encryption.Key)
		if err != nil {
			return event.Type{}, nil, err
		}
		return event.ToDeviceBeeperStreamEncrypted, &event.Content{Parsed: encrypted}, nil
	default:
		return logicalType, content, nil
	}
}

func decryptAndRewriteLogicalEvent(ctx context.Context, evt *event.Event, encrypted *event.BeeperStreamEncryptedEventContent, base64Key string, expectedType event.Type) bool {
	logicalType, parsedContent, err := decryptLogicalEvent(encrypted, base64Key)
	if err != nil {
		zerolog.Ctx(ctx).Debug().Err(err).
			Stringer("room_id", encrypted.RoomID).
			Stringer("event_id", encrypted.EventID).
			Msg("Failed to decrypt beeper stream event")
		return true
	}
	if logicalType != expectedType {
		return true
	}
	evt.Type = logicalType
	evt.Type.Class = event.ToDeviceEventType
	evt.Content = *parsedContent
	return false
}
