// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"context"
	"encoding/json"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type beeperStreamSubscription struct {
	key        beeperStreamKey
	descriptor *event.BeeperStreamInfo
	cancel     context.CancelFunc
}

func (m *BeeperStreamManager) Subscribe(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error {
	if err := descriptor.ValidateActive(); err != nil {
		return err
	}
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	m.lock.Lock()
	if existing := m.subscriptions[key]; existing != nil {
		if descriptorEqual(existing.descriptor, descriptor) {
			m.lock.Unlock()
			return nil
		}
		existing.cancel()
		delete(m.subscriptions, key)
	}
	subscribeCtx := context.Background()
	if ctx != nil {
		subscribeCtx = context.WithoutCancel(ctx)
	}
	subCtx, cancel := context.WithCancel(subscribeCtx)
	sub := &beeperStreamSubscription{
		key:        key,
		descriptor: descriptor.Clone(),
		cancel:     cancel,
	}
	m.subscriptions[key] = sub
	m.lock.Unlock()

	go m.runSubscriptionLoop(subCtx, sub)
	return nil
}

func (m *BeeperStreamManager) Unsubscribe(roomID id.RoomID, eventID id.EventID) {
	if m == nil {
		return
	}
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	m.lock.Lock()
	sub := m.subscriptions[key]
	if sub != nil {
		delete(m.subscriptions, key)
	}
	m.lock.Unlock()
	if sub != nil {
		sub.cancel()
	}
}

func (m *BeeperStreamManager) runSubscriptionLoop(ctx context.Context, sub *beeperStreamSubscription) {
	expiry := resolveSubscribeExpiry(sub.descriptor, DefaultBeeperStreamSubscribeExpiry)
	renewInterval := max(expiry/2, defaultBeeperStreamRenewInterval)
	if err := m.sendSubscribe(ctx, sub.key, sub.descriptor, expiry); err != nil && ctx.Err() == nil {
		m.log.Warn().Err(err).
			Stringer("room_id", sub.key.roomID).
			Stringer("event_id", sub.key.eventID).
			Msg("Failed to send initial beeper stream subscribe")
	}
	ticker := time.NewTicker(renewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.sendSubscribe(ctx, sub.key, sub.descriptor, expiry); err != nil && ctx.Err() == nil {
				m.log.Warn().Err(err).
					Stringer("room_id", sub.key.roomID).
					Stringer("event_id", sub.key.eventID).
					Msg("Failed to renew beeper stream subscribe")
			}
		}
	}
}

func (m *BeeperStreamManager) sendSubscribe(ctx context.Context, key beeperStreamKey, descriptor *event.BeeperStreamInfo, expiry time.Duration) error {
	client, err := m.requireClient(true)
	if err != nil {
		return err
	}
	subscribeContent := &event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
		RoomID:   key.roomID,
		EventID:  key.eventID,
		DeviceID: client.DeviceID,
		ExpiryMS: expiry.Milliseconds(),
	}}
	eventType := event.ToDeviceBeeperStreamSubscribe
	content := subscribeContent
	targetDevice := id.DeviceID("*")
	if descriptor.DeviceID != "" {
		targetDevice = descriptor.DeviceID
	}
	// Subscribers follow the publisher-provided descriptor wire contract.
	if descriptor.Encryption != nil {
		payload, err := json.Marshal(map[string]any{
			"device_id": client.DeviceID,
			"expiry_ms": expiry.Milliseconds(),
		})
		if err != nil {
			return err
		}
		encrypted, err := encryptLogicalEvent(event.ToDeviceBeeperStreamSubscribe, payload, key.roomID, key.eventID, descriptor.Encryption.Key)
		if err != nil {
			return err
		}
		eventType = event.ToDeviceBeeperStreamEncrypted
		content = &event.Content{Parsed: encrypted}
	}
	_, err = client.SendToDevice(ctx, eventType, &ReqSendToDevice{
		Messages: map[id.UserID]map[id.DeviceID]*event.Content{
			descriptor.UserID: {
				targetDevice: content,
			},
		},
	})
	return err
}

func (m *BeeperStreamManager) handlePlainUpdateEvent(evt *event.Event) {
	update := evt.Content.AsBeeperStreamUpdate()
	if update.RoomID == "" || update.EventID == "" {
		return
	}
	key := beeperStreamKey{roomID: update.RoomID, eventID: update.EventID}
	m.lock.RLock()
	sub := m.subscriptions[key]
	m.lock.RUnlock()
	if sub != nil && sub.descriptor.UserID != "" && evt.Sender != "" && evt.Sender != sub.descriptor.UserID {
		m.log.Warn().
			Stringer("sender", evt.Sender).
			Stringer("expected_user_id", sub.descriptor.UserID).
			Stringer("room_id", update.RoomID).
			Stringer("event_id", update.EventID).
			Msg("Beeper stream update from unexpected sender, dropping")
		return
	}
}

func (m *BeeperStreamManager) handleEncryptedForSubscriber(ctx context.Context, evt *event.Event, content *event.BeeperStreamEncryptedEventContent, sub *beeperStreamSubscription) *event.Event {
	normalized := decryptedLogicalEvent(ctx, evt, content, sub.descriptor.Encryption.Key, event.ToDeviceBeeperStreamUpdate)
	if normalized == nil {
		return nil
	}
	update := normalized.Content.AsBeeperStreamUpdate()
	if update.RoomID != sub.key.roomID || update.EventID != sub.key.eventID {
		return nil
	}
	if normalized.Sender != sub.descriptor.UserID {
		m.log.Warn().
			Stringer("sender", normalized.Sender).
			Stringer("expected_user_id", sub.descriptor.UserID).
			Stringer("room_id", update.RoomID).
			Stringer("event_id", update.EventID).
			Msg("Encrypted beeper stream update from unexpected sender, dropping")
		return nil
	}
	return normalized
}
