// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	// DefaultBeeperStreamDescriptorExpiry is the default lifetime of a beeper stream descriptor.
	DefaultBeeperStreamDescriptorExpiry = 30 * time.Minute
	// DefaultBeeperStreamSubscribeExpiry is the default lifetime of a beeper stream subscription.
	DefaultBeeperStreamSubscribeExpiry = 5 * time.Minute

	defaultBeeperStreamRenewInterval = 30 * time.Second
	beeperStreamCleanupGrace         = 30 * time.Second
	beeperStreamPendingSubscribeTTL  = 5 * time.Second
	maxPendingBeeperStreamSubs       = 64
	maxBeeperStreamUpdates           = 1024
)

type BeeperStreamManager struct {
	client *Client
	log    zerolog.Logger

	lock             sync.RWMutex
	publishedStreams map[beeperStreamKey]*beeperStreamPublished
	subscriptions    map[beeperStreamKey]*beeperStreamSubscription

	pendingLock      sync.Mutex
	pendingSubscribe []pendingSubscribeEvent

	now func() time.Time
}

type beeperStreamKey struct {
	roomID  id.RoomID
	eventID id.EventID
}

func (cli *Client) BeeperStreams() *BeeperStreamManager {
	if cli == nil {
		return nil
	}
	cli.beeperStreamLock.Lock()
	defer cli.beeperStreamLock.Unlock()
	if cli.beeperStream != nil {
		return cli.beeperStream
	}
	manager := &BeeperStreamManager{
		client:           cli,
		log:              cli.Log.With().Str("component", "beeper_stream").Logger(),
		publishedStreams: make(map[beeperStreamKey]*beeperStreamPublished),
		subscriptions:    make(map[beeperStreamKey]*beeperStreamSubscription),
		now:              time.Now,
	}
	manager.registerSyncHandlers()
	cli.beeperStream = manager
	return manager
}

func (m *BeeperStreamManager) registerSyncHandlers() {
	syncer, ok := m.client.Syncer.(ExtensibleSyncer)
	if !ok {
		return
	}
	syncer.OnEventType(event.ToDeviceBeeperStreamSubscribe, func(ctx context.Context, evt *event.Event) {
		m.handleEvent(ctx, evt)
	})
	dispatcher, ok := m.client.Syncer.(DispatchableSyncer)
	if !ok {
		return
	}
	syncer.OnEventType(event.ToDeviceBeeperStreamEncrypted, func(ctx context.Context, evt *event.Event) {
		if normalized := m.handleEvent(ctx, evt); normalized != nil {
			dispatcher.Dispatch(ctx, normalized)
		}
	})
}

func (m *BeeperStreamManager) NewDescriptor(ctx context.Context, roomID id.RoomID, streamType string) (*event.BeeperStreamInfo, error) {
	if m == nil {
		return nil, fmt.Errorf("beeper stream manager is nil")
	} else if roomID == "" || streamType == "" {
		return nil, fmt.Errorf("missing beeper stream descriptor request fields")
	}
	client, err := m.requireClient(false)
	if err != nil {
		return nil, err
	}
	info := &event.BeeperStreamInfo{
		UserID:   client.UserID,
		DeviceID: client.DeviceID,
		Type:     streamType,
		ExpiryMS: DefaultBeeperStreamDescriptorExpiry.Milliseconds(),
		Status:   event.BeeperStreamStatusActive,
	}
	if m.isEncrypted(ctx, roomID) {
		info.Encryption = &event.BeeperStreamEncryptionInfo{
			Algorithm: id.AlgorithmBeeperStreamAESGCM,
			Key:       makeStreamKey(),
		}
	}
	return info, nil
}

func (m *BeeperStreamManager) HandleToDeviceEvent(ctx context.Context, evt *event.Event) *event.Event {
	return m.handleEvent(ctx, evt)
}

func (m *BeeperStreamManager) handleEvent(ctx context.Context, evt *event.Event) *event.Event {
	if m == nil || evt == nil {
		return nil
	}
	switch evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		m.handleSubscribeEvent(ctx, evt)
	case event.ToDeviceBeeperStreamEncrypted:
		return m.handleEncryptedEvent(ctx, evt)
	}
	return nil
}

func (m *BeeperStreamManager) handleEncryptedEvent(ctx context.Context, evt *event.Event) *event.Event {
	content := evt.Content.AsBeeperStreamEncrypted()
	if content.RoomID == "" || content.EventID == "" || content.Ciphertext == "" {
		return nil
	}
	key := beeperStreamKey{roomID: content.RoomID, eventID: content.EventID}
	m.lock.RLock()
	published := m.publishedStreams[key]
	sub := m.subscriptions[key]
	m.lock.RUnlock()
	if published != nil {
		return m.handleEncryptedForPublisher(ctx, evt, content, published)
	}
	if sub != nil {
		return m.handleEncryptedForSubscriber(ctx, evt, content, sub)
	}
	m.queuePendingSubscribe(ctx, evt)
	return nil
}

func decryptedLogicalEvent(ctx context.Context, evt *event.Event, encrypted *event.BeeperStreamEncryptedEventContent, base64Key string, expectedType event.Type) *event.Event {
	logicalType, payload, err := decryptLogicalEvent(encrypted, base64Key)
	if err != nil {
		zerolog.Ctx(ctx).Debug().Err(err).
			Stringer("room_id", encrypted.RoomID).
			Stringer("event_id", encrypted.EventID).
			Msg("Failed to decrypt beeper stream event")
		return nil
	}
	if logicalType != expectedType {
		return nil
	}
	var raw map[string]any
	if err = json.Unmarshal(payload, &raw); err != nil {
		return nil
	}
	parsed, err := contentFromRawMap(addStreamRouting(raw, encrypted.RoomID, encrypted.EventID))
	if err != nil || parsed.ParseRaw(logicalType) != nil {
		return nil
	}
	normalized := *evt
	normalized.Type = logicalType
	normalized.Type.Class = event.ToDeviceEventType
	normalized.Content = *parsed
	return &normalized
}

func rawMapFromContent(content *event.Content) (map[string]any, error) {
	if content == nil {
		return map[string]any{}, nil
	}
	if content.Raw != nil {
		return maps.Clone(content.Raw), nil
	}
	if len(content.VeryRaw) == 0 {
		return map[string]any{}, nil
	}
	var raw map[string]any
	err := json.Unmarshal(content.VeryRaw, &raw)
	if raw == nil {
		raw = make(map[string]any)
	}
	return raw, err
}

func contentFromRawMap(raw map[string]any) (*event.Content, error) {
	if raw == nil {
		raw = make(map[string]any)
	}
	veryRaw, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	return &event.Content{VeryRaw: veryRaw, Raw: maps.Clone(raw)}, nil
}

func addStreamRouting(raw map[string]any, roomID id.RoomID, eventID id.EventID) map[string]any {
	withRouting := maps.Clone(raw)
	if withRouting == nil {
		withRouting = make(map[string]any, 2)
	}
	withRouting["room_id"] = roomID
	withRouting["event_id"] = eventID
	return withRouting
}

func removeStreamRouting(raw map[string]any) map[string]any {
	withoutRouting := maps.Clone(raw)
	if withoutRouting == nil {
		return make(map[string]any)
	}
	delete(withoutRouting, "room_id")
	delete(withoutRouting, "event_id")
	return withoutRouting
}

func (m *BeeperStreamManager) isEncrypted(ctx context.Context, roomID id.RoomID) bool {
	if m == nil || m.client == nil || m.client.StateStore == nil {
		return false
	}
	encrypted, err := m.client.StateStore.IsEncrypted(ctx, roomID)
	return err == nil && encrypted
}

func (m *BeeperStreamManager) isForDifferentUser(evt *event.Event) bool {
	if m == nil || m.client == nil || evt == nil {
		return false
	}
	return evt.ToUserID != "" && evt.ToUserID != m.client.UserID
}

func (m *BeeperStreamManager) requireClient(requireDevice bool) (*Client, error) {
	if m == nil || m.client == nil {
		return nil, fmt.Errorf("beeper stream manager doesn't have a client")
	} else if m.client.UserID == "" {
		return nil, fmt.Errorf("beeper stream client isn't logged in")
	} else if requireDevice && m.client.DeviceID == "" {
		return nil, fmt.Errorf("beeper stream client doesn't have a device ID")
	}
	return m.client, nil
}

func resolveSubscribeExpiry(descriptor *event.BeeperStreamInfo, fallback time.Duration) time.Duration {
	if fallback <= 0 {
		fallback = DefaultBeeperStreamSubscribeExpiry
	}
	if descriptor != nil && descriptor.ExpiryMS > 0 {
		descriptorExpiry := time.Duration(descriptor.ExpiryMS) * time.Millisecond
		if descriptorExpiry < fallback {
			return descriptorExpiry
		}
	}
	return fallback
}

func descriptorEqual(a, b *event.BeeperStreamInfo) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	case a.UserID != b.UserID || a.DeviceID != b.DeviceID || a.Type != b.Type || a.ExpiryMS != b.ExpiryMS || a.Status != b.Status:
		return false
	case a.Encryption == nil || b.Encryption == nil:
		return a.Encryption == b.Encryption
	default:
		return a.Encryption.Algorithm == b.Encryption.Algorithm &&
			a.Encryption.Key == b.Encryption.Key
	}
}
