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
	"slices"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type beeperStreamSubscriber struct {
	userID   id.UserID
	deviceID id.DeviceID
}

type beeperStreamPublished struct {
	key        beeperStreamKey
	descriptor *event.BeeperStreamInfo
	updates    []*event.Content

	subscribers  map[beeperStreamSubscriber]time.Time
	inactive     bool
	cleanup      *time.Timer
	lastEviction time.Time
}

type pendingSubscribeEvent struct {
	key        beeperStreamKey
	evt        *event.Event
	receivedAt time.Time
}

func (m *BeeperStreamManager) Register(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error {
	if err := descriptor.ValidateActive(); err != nil {
		return err
	}
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	state := &beeperStreamPublished{
		key:         key,
		descriptor:  descriptor.Clone(),
		subscribers: make(map[beeperStreamSubscriber]time.Time),
	}
	m.lock.Lock()
	if existing := m.publishedStreams[key]; existing != nil {
		if descriptorEqual(existing.descriptor, state.descriptor) {
			m.lock.Unlock()
			m.replayPendingSubscribe(ctx, key)
			return nil
		}
		if existing.cleanup != nil {
			existing.cleanup.Stop()
		}
	}
	m.publishedStreams[key] = state
	m.lock.Unlock()
	m.replayPendingSubscribe(ctx, key)
	return nil
}

func (m *BeeperStreamManager) Unregister(roomID id.RoomID, eventID id.EventID) {
	if m == nil {
		return
	}
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	m.lock.Lock()
	state := m.publishedStreams[key]
	if state == nil {
		m.lock.Unlock()
		return
	}
	state.inactive = true
	state.subscribers = nil
	if state.cleanup != nil {
		state.cleanup.Stop()
	}
	state.cleanup = time.AfterFunc(beeperStreamCleanupGrace, func() {
		m.lock.Lock()
		delete(m.publishedStreams, key)
		m.lock.Unlock()
	})
	m.lock.Unlock()
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
	return contentFromRawMap(addStreamRouting(content, roomID, eventID))
}

func streamUpdateIdentifiers(content *event.Content) (*event.BeeperStreamUpdateEventContent, error) {
	update := content.AsBeeperStreamUpdate()
	if update.RoomID != "" && update.EventID != "" {
		return update, nil
	}
	raw, err := rawMapFromContent(content)
	if err != nil {
		return nil, err
	}
	return &event.BeeperStreamUpdateEventContent{
		RoomID:  id.RoomID(fmt.Sprint(raw["room_id"])),
		EventID: id.EventID(fmt.Sprint(raw["event_id"])),
	}, nil
}

func (m *BeeperStreamManager) Publish(ctx context.Context, roomID id.RoomID, eventID id.EventID, delta map[string]any) error {
	update, err := newUpdateContent(roomID, eventID, delta)
	if err != nil {
		return err
	}
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	m.lock.Lock()
	state := m.publishedStreams[key]
	if state == nil {
		m.lock.Unlock()
		return fmt.Errorf("beeper stream %s/%s not found", roomID, eventID)
	} else if state.inactive {
		m.lock.Unlock()
		return fmt.Errorf("beeper stream %s/%s is inactive", roomID, eventID)
	}
	state.updates = append(state.updates, update)
	if len(state.updates) > maxBeeperStreamUpdates {
		state.updates = state.updates[len(state.updates)-maxBeeperStreamUpdates:]
	}
	descriptor := state.descriptor.Clone()
	subscribers := state.activeSubscribers(m.now())
	m.lock.Unlock()
	return m.sendUpdate(ctx, descriptor, update, subscribers)
}

func (m *BeeperStreamManager) handleSubscribeEvent(ctx context.Context, evt *event.Event) {
	if m.isForDifferentUser(evt) {
		return
	}
	subscribe := evt.Content.AsBeeperStreamSubscribe()
	if subscribe.RoomID == "" || subscribe.EventID == "" {
		return
	}
	if m.handleSubscribe(ctx, evt.Sender, subscribe) {
		return
	}
	m.queuePendingSubscribe(ctx, evt)
}

func (m *BeeperStreamManager) handleEncryptedForPublisher(ctx context.Context, evt *event.Event, content *event.BeeperStreamEncryptedEventContent, state *beeperStreamPublished) *event.Event {
	if state.descriptor == nil || state.descriptor.Encryption == nil {
		return nil
	}
	normalized := decryptedLogicalEvent(ctx, evt, content, state.descriptor.Encryption.Key, event.ToDeviceBeeperStreamSubscribe)
	if normalized == nil {
		return nil
	}
	m.handleSubscribeEvent(ctx, normalized)
	return nil
}

func (m *BeeperStreamManager) handleSubscribe(ctx context.Context, sender id.UserID, subscribe *event.BeeperStreamSubscribeEventContent) bool {
	if subscribe == nil {
		return false
	}
	key := beeperStreamKey{roomID: subscribe.RoomID, eventID: subscribe.EventID}
	m.lock.Lock()
	state := m.publishedStreams[key]
	if state == nil {
		m.lock.Unlock()
		return false
	} else if state.inactive {
		m.lock.Unlock()
		return true
	}
	expiry := resolveSubscribeExpiry(state.descriptor, time.Duration(subscribe.ExpiryMS)*time.Millisecond)
	subscriber := beeperStreamSubscriber{userID: sender, deviceID: subscribe.DeviceID}
	state.subscribers[subscriber] = m.now().Add(expiry)
	descriptor := state.descriptor.Clone()
	updates := slices.Clone(state.updates)
	m.lock.Unlock()

	for _, update := range updates {
		if err := m.sendUpdate(ctx, descriptor, update, []beeperStreamSubscriber{subscriber}); err != nil {
			m.lock.Lock()
			state = m.publishedStreams[key]
			if state != nil {
				delete(state.subscribers, subscriber)
			}
			m.lock.Unlock()
			return true
		}
	}
	return true
}

func (m *BeeperStreamManager) sendUpdate(ctx context.Context, descriptor *event.BeeperStreamInfo, update *event.Content, subscribers []beeperStreamSubscriber) error {
	if len(subscribers) == 0 {
		return nil
	}
	client, err := m.requireClient(false)
	if err != nil {
		return err
	}
	eventType := event.ToDeviceBeeperStreamUpdate
	content := update
	if descriptor != nil && descriptor.Encryption != nil {
		updateInfo, err := streamUpdateIdentifiers(update)
		if err != nil {
			return err
		}
		raw, err := rawMapFromContent(update)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(removeStreamRouting(raw))
		if err != nil {
			return err
		}
		encrypted, err := encryptLogicalEvent(event.ToDeviceBeeperStreamUpdate, payload, updateInfo.RoomID, updateInfo.EventID, descriptor.Encryption.Key)
		if err != nil {
			return err
		}
		eventType = event.ToDeviceBeeperStreamEncrypted
		content = &event.Content{Parsed: encrypted}
	}
	req := &ReqSendToDevice{
		Messages: make(map[id.UserID]map[id.DeviceID]*event.Content, len(subscribers)),
	}
	for _, subscriber := range subscribers {
		if req.Messages[subscriber.userID] == nil {
			req.Messages[subscriber.userID] = make(map[id.DeviceID]*event.Content)
		}
		req.Messages[subscriber.userID][subscriber.deviceID] = content
	}
	_, err = client.SendToDevice(ctx, eventType, req)
	return err
}

func (m *BeeperStreamManager) queuePendingSubscribe(ctx context.Context, evt *event.Event) {
	key, ok := pendingSubscribeKey(evt)
	if !ok {
		return
	}
	now := m.now()
	m.pendingLock.Lock()
	m.pendingSubscribe = append(m.pendingSubscribe, pendingSubscribeEvent{
		key:        key,
		evt:        evt,
		receivedAt: now,
	})
	pendingCount := len(m.pendingSubscribe)
	if pendingCount > maxPendingBeeperStreamSubs {
		m.pendingSubscribe = m.pendingSubscribe[len(m.pendingSubscribe)-maxPendingBeeperStreamSubs:]
		pendingCount = len(m.pendingSubscribe)
	}
	m.pendingLock.Unlock()
	zerolog.Ctx(ctx).Debug().
		Int("pending_subscribes", pendingCount).
		Stringer("sender", evt.Sender).
		Str("event_type", evt.Type.Type).
		Msg("Queued subscribe for possible future beeper stream registration")
}

func (m *BeeperStreamManager) replayPendingSubscribe(ctx context.Context, key beeperStreamKey) {
	now := m.now()
	m.pendingLock.Lock()
	if len(m.pendingSubscribe) == 0 {
		m.pendingLock.Unlock()
		return
	}
	var replay []pendingSubscribeEvent
	filtered := m.pendingSubscribe[:0]
	for _, candidate := range m.pendingSubscribe {
		if candidate.evt == nil || now.Sub(candidate.receivedAt) > beeperStreamPendingSubscribeTTL {
			continue
		}
		if candidate.key == key {
			replay = append(replay, candidate)
			continue
		}
		filtered = append(filtered, candidate)
	}
	m.pendingSubscribe = filtered
	m.pendingLock.Unlock()
	if len(replay) == 0 {
		return
	}
	var failed []pendingSubscribeEvent
	for _, candidate := range replay {
		if !m.tryPendingSubscribe(ctx, candidate) {
			failed = append(failed, candidate)
		}
	}
	if len(failed) == 0 {
		return
	}
	m.pendingLock.Lock()
	m.pendingSubscribe = append(m.pendingSubscribe, failed...)
	if len(m.pendingSubscribe) > maxPendingBeeperStreamSubs {
		m.pendingSubscribe = m.pendingSubscribe[len(m.pendingSubscribe)-maxPendingBeeperStreamSubs:]
	}
	m.pendingLock.Unlock()
}

func (m *BeeperStreamManager) tryPendingSubscribe(ctx context.Context, candidate pendingSubscribeEvent) bool {
	switch candidate.evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		subscribe := candidate.evt.Content.AsBeeperStreamSubscribe()
		if subscribe.RoomID == "" || subscribe.EventID == "" {
			return false
		}
		return m.handleSubscribe(ctx, candidate.evt.Sender, subscribe)
	case event.ToDeviceBeeperStreamEncrypted:
		content := candidate.evt.Content.AsBeeperStreamEncrypted()
		if content.RoomID == "" || content.EventID == "" {
			return false
		}
		m.lock.RLock()
		state := m.publishedStreams[candidate.key]
		m.lock.RUnlock()
		if state == nil {
			return false
		}
		m.handleEncryptedForPublisher(ctx, candidate.evt, content, state)
		return true
	default:
		return false
	}
}

func pendingSubscribeKey(evt *event.Event) (beeperStreamKey, bool) {
	if evt == nil {
		return beeperStreamKey{}, false
	}
	switch evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		content := evt.Content.AsBeeperStreamSubscribe()
		if content.RoomID == "" || content.EventID == "" {
			return beeperStreamKey{}, false
		}
		return beeperStreamKey{roomID: content.RoomID, eventID: content.EventID}, true
	case event.ToDeviceBeeperStreamEncrypted:
		content := evt.Content.AsBeeperStreamEncrypted()
		if content.RoomID == "" || content.EventID == "" {
			return beeperStreamKey{}, false
		}
		return beeperStreamKey{roomID: content.RoomID, eventID: content.EventID}, true
	default:
		return beeperStreamKey{}, false
	}
}

func (state *beeperStreamPublished) activeSubscribers(now time.Time) []beeperStreamSubscriber {
	var active []beeperStreamSubscriber
	doEvict := now.Sub(state.lastEviction) >= beeperStreamCleanupGrace
	for subscriber, expiry := range state.subscribers {
		if now.After(expiry) {
			if doEvict {
				delete(state.subscribers, subscriber)
			}
			continue
		}
		active = append(active, subscriber)
	}
	if doEvict {
		state.lastEviction = now
	}
	return active
}
