// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, you can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/random"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	// DefaultBeeperStreamDescriptorExpiry is the default lifetime of a beeper stream descriptor.
	DefaultBeeperStreamDescriptorExpiry = 30 * time.Minute
	// DefaultBeeperStreamSubscribeExpiry is the default lifetime of a beeper stream subscription.
	DefaultBeeperStreamSubscribeExpiry = 5 * time.Minute

	defaultBeeperStreamRenewInterval = 30 * time.Second
	streamCleanupGrace               = 30 * time.Second
	pendingSubscribeTTL              = 5 * time.Second
	maxPendingSubscribes             = 64
	maxUpdatesPerStream              = 1024

	beeperStreamComponentName         = "beeper_stream"
	beeperStreamReceiverComponentName = "beeper_stream_receiver"
)

type beeperStreamKey struct {
	roomID  id.RoomID
	eventID id.EventID
}

type beeperStreamSubscriber struct {
	userID   id.UserID
	deviceID id.DeviceID
}

type beeperStreamState struct {
	key        beeperStreamKey
	descriptor *event.BeeperStreamInfo
	updates    []*event.Content

	subscribers  map[beeperStreamSubscriber]time.Time
	finished     bool
	cleanup      *time.Timer
	lastEviction time.Time

	gcm cipher.AEAD
}

type beeperStreamEncryptedPayload struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

type pendingSubscribeEvent struct {
	evt        *event.Event
	receivedAt time.Time
}

func resolveStreamLogger(optsLogger *zerolog.Logger, client *Client, component string) zerolog.Logger {
	switch {
	case optsLogger != nil:
		return optsLogger.With().Str("component", component).Logger()
	case client != nil:
		return client.Log.With().Str("component", component).Logger()
	default:
		return zerolog.Nop()
	}
}

func requireStreamSenderClient(client *Client, role string) (*Client, error) {
	if client == nil {
		return nil, fmt.Errorf("beeper stream %s doesn't have a client", role)
	} else if client.UserID == "" {
		return nil, fmt.Errorf("beeper stream %s client isn't logged in", role)
	}
	return client, nil
}

func requireStreamReceiverClient(client *Client, role string) (*Client, error) {
	client, err := requireStreamSenderClient(client, role)
	if err != nil {
		return nil, err
	} else if client.DeviceID == "" {
		return nil, fmt.Errorf("beeper stream %s client doesn't have a device ID", role)
	}
	return client, nil
}

func beeperStreamDescriptorEqual(a, b *event.BeeperStreamInfo) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	case a.UserID != b.UserID || a.Type != b.Type || a.ExpiryMS != b.ExpiryMS:
		return false
	case a.Encryption == nil || b.Encryption == nil:
		return a.Encryption == b.Encryption
	default:
		return a.Encryption.Algorithm == b.Encryption.Algorithm && a.Encryption.Key == b.Encryption.Key && a.Encryption.StreamID == b.Encryption.StreamID
	}
}

func resolveBeeperStreamSubscribeExpiry(descriptor *event.BeeperStreamInfo, defaultExpiry time.Duration) time.Duration {
	expiry := defaultExpiry
	if expiry <= 0 {
		expiry = DefaultBeeperStreamSubscribeExpiry
	}
	if descriptor != nil && descriptor.ExpiryMS > 0 {
		descriptorExpiry := time.Duration(descriptor.ExpiryMS) * time.Millisecond
		if descriptorExpiry < expiry {
			expiry = descriptorExpiry
		}
	}
	return expiry
}

func validateBeeperStreamDescriptor(info *event.BeeperStreamInfo) error {
	if info == nil {
		return fmt.Errorf("missing beeper stream descriptor")
	} else if info.UserID == "" || info.Type == "" {
		return fmt.Errorf("missing beeper stream descriptor fields")
	}
	if info.Encryption == nil {
		return nil
	}
	if info.Encryption.Algorithm != id.AlgorithmBeeperStreamAESGCM {
		return fmt.Errorf("unsupported beeper stream encryption algorithm %q", info.Encryption.Algorithm)
	} else if info.Encryption.Key == "" {
		return fmt.Errorf("missing beeper stream encryption key")
	} else if info.Encryption.StreamID == "" {
		return fmt.Errorf("missing beeper stream encryption stream_id")
	}
	return nil
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

func encryptStreamPayload(logicalType event.Type, payload *event.Content, streamID id.StreamID, gcm cipher.AEAD) (*event.EncryptedEventContent, error) {
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

func decryptStreamPayload(content *event.EncryptedEventContent, gcm cipher.AEAD) (*beeperStreamEncryptedPayload, error) {
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

func newStreamUpdateContent(roomID id.RoomID, eventID id.EventID, content map[string]any) (*event.Content, error) {
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
