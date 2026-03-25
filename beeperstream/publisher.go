// Copyright (c) 2026 Batuhan İçöz
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package beeperstream

import (
	"context"
	"fmt"
	"slices"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type subscriber struct {
	userID   id.UserID
	deviceID id.DeviceID
}

type publishedStream struct {
	descriptor         *event.BeeperStreamInfo
	streamID           string
	maxBufferedUpdates int
	updates            []*event.Content

	subscribers  map[subscriber]time.Time
	inactive     bool
	cleanup      *time.Timer
	lastEviction time.Time
}

type pendingSubscribeEvent struct {
	key        streamKey
	streamID   string
	evt        *event.Event
	receivedAt time.Time
}

func (h *Helper) Register(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error {
	if h == nil {
		return fmt.Errorf("beeper stream helper is nil")
	} else if h.closed.Load() {
		return fmt.Errorf("beeper stream helper is closed")
	} else if err := descriptor.Validate(); err != nil {
		return err
	}
	key := streamKey{roomID: roomID, eventID: eventID}
	state := &publishedStream{
		descriptor:         descriptor.Clone(),
		maxBufferedUpdates: resolveMaxBufferedUpdates(descriptor),
		subscribers:        make(map[subscriber]time.Time),
	}
	if descriptor.Encryption != nil {
		state.streamID = deriveStreamID(descriptor.Encryption.Key, roomID, eventID)
	}
	h.lock.Lock()
	if existing := h.publishedStreams[key]; existing != nil {
		if descriptorEqual(existing.descriptor, state.descriptor) {
			h.lock.Unlock()
			h.replayPendingSubscribe(ctx, key)
			return nil
		}
		if existing.streamID != "" {
			delete(h.encryptedPubl, existing.streamID)
		}
		if existing.cleanup != nil {
			existing.cleanup.Stop()
		}
	}
	h.publishedStreams[key] = state
	if state.streamID != "" {
		h.encryptedPubl[state.streamID] = key
	}
	h.lock.Unlock()
	h.replayPendingSubscribe(ctx, key)
	return nil
}

func (h *Helper) Unregister(roomID id.RoomID, eventID id.EventID) {
	if h == nil || h.closed.Load() {
		return
	}
	key := streamKey{roomID: roomID, eventID: eventID}
	h.lock.Lock()
	state := h.publishedStreams[key]
	if state == nil {
		h.lock.Unlock()
		return
	}
	state.inactive = true
	state.subscribers = nil
	if state.streamID != "" {
		delete(h.encryptedPubl, state.streamID)
	}
	if state.cleanup != nil {
		state.cleanup.Stop()
	}
	state.cleanup = time.AfterFunc(cleanupGrace, func() {
		h.lock.Lock()
		delete(h.publishedStreams, key)
		h.lock.Unlock()
	})
	h.lock.Unlock()
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

func (h *Helper) Publish(ctx context.Context, roomID id.RoomID, eventID id.EventID, delta map[string]any) error {
	if h == nil {
		return fmt.Errorf("beeper stream helper is nil")
	} else if h.closed.Load() {
		return fmt.Errorf("beeper stream helper is closed")
	}
	update, err := normalizeUpdateContent(roomID, eventID, delta)
	if err != nil {
		return err
	}
	key := streamKey{roomID: roomID, eventID: eventID}
	h.lock.Lock()
	state := h.publishedStreams[key]
	if state == nil {
		h.lock.Unlock()
		return fmt.Errorf("beeper stream %s/%s not found", roomID, eventID)
	} else if state.inactive {
		h.lock.Unlock()
		return fmt.Errorf("beeper stream %s/%s is inactive", roomID, eventID)
	}
	state.updates = append(state.updates, update)
	if len(state.updates) > state.maxBufferedUpdates {
		state.updates = state.updates[len(state.updates)-state.maxBufferedUpdates:]
	}
	descriptor := state.descriptor.Clone()
	subscribers := state.activeSubscribers(h.now())
	h.lock.Unlock()
	return h.sendUpdate(ctx, descriptor, update, subscribers)
}

func (h *Helper) handleSubscribeEvent(ctx context.Context, evt *event.Event) {
	subscribe := evt.Content.AsBeeperStreamSubscribe()
	if subscribe.RoomID == "" || subscribe.EventID == "" {
		return
	}
	if h.handleSubscribe(ctx, evt.Sender, subscribe) {
		return
	}
	h.queuePendingSubscribe(ctx, evt)
}

func (h *Helper) handleEncryptedForPublisher(ctx context.Context, evt *event.Event, key streamKey, state *publishedStream) []*event.Event {
	if state.descriptor == nil || state.descriptor.Encryption == nil {
		return nil
	}
	normalized := decryptedLogicalEvent(ctx, evt, state.descriptor.Encryption.Key, key, event.ToDeviceBeeperStreamSubscribe)
	if normalized == nil {
		return nil
	}
	h.handleSubscribeEvent(ctx, normalized)
	return nil
}

func (h *Helper) handleSubscribe(ctx context.Context, sender id.UserID, subscribe *event.BeeperStreamSubscribeEventContent) bool {
	if subscribe == nil {
		return false
	}
	key := streamKey{roomID: subscribe.RoomID, eventID: subscribe.EventID}
	h.lock.Lock()
	state := h.publishedStreams[key]
	if state == nil {
		h.lock.Unlock()
		return false
	} else if state.inactive {
		h.lock.Unlock()
		return true
	}
	expiry := resolveSubscribeExpiry(state.descriptor, time.Duration(subscribe.ExpiryMS)*time.Millisecond)
	sub := subscriber{userID: sender, deviceID: subscribe.DeviceID}
	state.subscribers[sub] = h.now().Add(expiry)
	descriptor := state.descriptor.Clone()
	updates := slices.Clone(state.updates)
	h.lock.Unlock()

	if err := h.sendReplayUpdates(ctx, descriptor, updates, []subscriber{sub}); err != nil {
		h.lock.Lock()
		state = h.publishedStreams[key]
		if state != nil {
			delete(state.subscribers, sub)
		}
		h.lock.Unlock()
		return true
	}
	return true
}

func makeReplayUpdateContent(updates []*event.Content) (*event.Content, error) {
	if len(updates) == 0 {
		return nil, nil
	} else if len(updates) == 1 {
		return updates[0], nil
	}
	updateInfo, err := streamUpdateIdentifiers(updates[0])
	if err != nil {
		return nil, err
	}
	batched := make([]map[string]any, 0, len(updates))
	for _, update := range updates {
		raw, err := rawMapFromContent(update)
		if err != nil {
			return nil, err
		}
		batched = append(batched, stripUpdateRouting(raw))
	}
	return contentFromRawMap(map[string]any{
		"room_id":  updateInfo.RoomID,
		"event_id": updateInfo.EventID,
		"updates":  batched,
	})
}

func (h *Helper) sendReplayUpdates(ctx context.Context, descriptor *event.BeeperStreamInfo, updates []*event.Content, subscribers []subscriber) error {
	content, err := makeReplayUpdateContent(updates)
	if err != nil || content == nil {
		return err
	}
	return h.sendUpdate(ctx, descriptor, content, subscribers)
}

func (h *Helper) sendUpdate(ctx context.Context, descriptor *event.BeeperStreamInfo, update *event.Content, subscribers []subscriber) error {
	if len(subscribers) == 0 {
		return nil
	}
	client, err := h.requireClient(false)
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
		payload, err := marshalContent(update)
		if err != nil {
			return err
		}
		encContent, err := encryptLogicalEvent(event.ToDeviceBeeperStreamUpdate, payload, updateInfo.RoomID, updateInfo.EventID, descriptor.Encryption.Key)
		if err != nil {
			return err
		}
		eventType = event.ToDeviceEncrypted
		content = encContent
	}
	req := &mautrix.ReqSendToDevice{
		Messages: make(map[id.UserID]map[id.DeviceID]*event.Content, len(subscribers)),
	}
	for _, sub := range subscribers {
		if req.Messages[sub.userID] == nil {
			req.Messages[sub.userID] = make(map[id.DeviceID]*event.Content)
		}
		req.Messages[sub.userID][sub.deviceID] = content
	}
	_, err = client.SendToDevice(ctx, eventType, req)
	return err
}

func (h *Helper) queuePendingSubscribe(ctx context.Context, evt *event.Event) {
	key, streamID, ok := pendingSubscribeKey(evt)
	if !ok || h.closed.Load() {
		return
	}
	now := h.now()
	h.pendingLock.Lock()
	h.pendingSubscribe = append(h.pendingSubscribe, pendingSubscribeEvent{
		key:        key,
		streamID:   streamID,
		evt:        evt,
		receivedAt: now,
	})
	pendingCount := len(h.pendingSubscribe)
	if pendingCount > maxPendingSubscriptions {
		h.pendingSubscribe = h.pendingSubscribe[len(h.pendingSubscribe)-maxPendingSubscriptions:]
		pendingCount = len(h.pendingSubscribe)
	}
	h.pendingLock.Unlock()
	h.log.Debug().
		Int("pending_subscribes", pendingCount).
		Stringer("sender", evt.Sender).
		Str("event_type", evt.Type.Type).
		Msg("Queued subscribe for possible future beeper stream registration")
}

func (h *Helper) replayPendingSubscribe(ctx context.Context, key streamKey) {
	now := h.now()
	h.lock.RLock()
	state := h.publishedStreams[key]
	streamID := ""
	if state != nil {
		streamID = state.streamID
	}
	h.lock.RUnlock()
	h.pendingLock.Lock()
	if len(h.pendingSubscribe) == 0 {
		h.pendingLock.Unlock()
		return
	}
	var replay []pendingSubscribeEvent
	filtered := h.pendingSubscribe[:0]
	for _, candidate := range h.pendingSubscribe {
		if candidate.evt == nil || now.Sub(candidate.receivedAt) > pendingSubscribeTTL {
			continue
		}
		if candidate.key == key || (streamID != "" && candidate.streamID == streamID) {
			replay = append(replay, candidate)
			continue
		}
		filtered = append(filtered, candidate)
	}
	h.pendingSubscribe = filtered
	h.pendingLock.Unlock()
	if len(replay) == 0 {
		return
	}
	var failed []pendingSubscribeEvent
	for _, candidate := range replay {
		if !h.tryPendingSubscribe(ctx, candidate) {
			failed = append(failed, candidate)
		}
	}
	if len(failed) == 0 {
		return
	}
	h.pendingLock.Lock()
	h.pendingSubscribe = append(h.pendingSubscribe, failed...)
	if len(h.pendingSubscribe) > maxPendingSubscriptions {
		h.pendingSubscribe = h.pendingSubscribe[len(h.pendingSubscribe)-maxPendingSubscriptions:]
	}
	h.pendingLock.Unlock()
}

func (h *Helper) tryPendingSubscribe(ctx context.Context, candidate pendingSubscribeEvent) bool {
	switch candidate.evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		subscribe := candidate.evt.Content.AsBeeperStreamSubscribe()
		if subscribe.RoomID == "" || subscribe.EventID == "" {
			return false
		}
		return h.handleSubscribe(ctx, candidate.evt.Sender, subscribe)
	case event.ToDeviceEncrypted:
		content := candidate.evt.Content.AsEncrypted()
		if content.Algorithm != id.AlgorithmBeeperStreamV1 {
			return false
		}
		if content.StreamID == "" || len(content.BeeperStreamCiphertext) == 0 {
			return false
		}
		h.lock.RLock()
		key, ok := h.encryptedPubl[content.StreamID]
		state := h.publishedStreams[key]
		h.lock.RUnlock()
		if !ok || state == nil {
			return false
		}
		h.handleEncryptedForPublisher(ctx, candidate.evt, key, state)
		return true
	default:
		return false
	}
}

func pendingSubscribeKey(evt *event.Event) (streamKey, string, bool) {
	if evt == nil {
		return streamKey{}, "", false
	}
	switch evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		content := evt.Content.AsBeeperStreamSubscribe()
		if content.RoomID == "" || content.EventID == "" {
			return streamKey{}, "", false
		}
		return streamKey{roomID: content.RoomID, eventID: content.EventID}, "", true
	case event.ToDeviceEncrypted:
		content := evt.Content.AsEncrypted()
		if content.Algorithm != id.AlgorithmBeeperStreamV1 {
			return streamKey{}, "", false
		}
		if content.StreamID == "" || len(content.BeeperStreamCiphertext) == 0 {
			return streamKey{}, "", false
		}
		return streamKey{}, content.StreamID, true
	default:
		return streamKey{}, "", false
	}
}

func (state *publishedStream) activeSubscribers(now time.Time) []subscriber {
	var active []subscriber
	doEvict := now.Sub(state.lastEviction) >= cleanupGrace
	for sub, expiry := range state.subscribers {
		if now.After(expiry) {
			if doEvict {
				delete(state.subscribers, sub)
			}
			continue
		}
		active = append(active, sub)
	}
	if doEvict {
		state.lastEviction = now
	}
	return active
}
