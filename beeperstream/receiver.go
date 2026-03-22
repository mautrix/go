// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package beeperstream

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type subscription struct {
	key        streamKey
	descriptor *event.BeeperStreamInfo
	cancel     context.CancelFunc
}

func (h *Helper) Subscribe(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error {
	if h == nil {
		return fmt.Errorf("beeper stream helper is nil")
	} else if h.closed.Load() {
		return fmt.Errorf("beeper stream helper is closed")
	} else if err := descriptor.Validate(); err != nil {
		return err
	}
	key := streamKey{roomID: roomID, eventID: eventID}
	h.lock.Lock()
	if existing := h.subscriptions[key]; existing != nil {
		if descriptorEqual(existing.descriptor, descriptor) {
			h.lock.Unlock()
			return nil
		}
		existing.cancel()
		delete(h.subscriptions, key)
	}
	subCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	sub := &subscription{
		key:        key,
		descriptor: descriptor.Clone(),
		cancel:     cancel,
	}
	h.subscriptions[key] = sub
	h.lock.Unlock()

	go h.runSubscriptionLoop(subCtx, sub)
	return nil
}

func (h *Helper) Unsubscribe(roomID id.RoomID, eventID id.EventID) {
	if h == nil || h.closed.Load() {
		return
	}
	key := streamKey{roomID: roomID, eventID: eventID}
	h.lock.Lock()
	sub := h.subscriptions[key]
	if sub != nil {
		delete(h.subscriptions, key)
	}
	h.lock.Unlock()
	if sub != nil {
		sub.cancel()
	}
}

func (h *Helper) runSubscriptionLoop(ctx context.Context, sub *subscription) {
	expiry := resolveSubscribeExpiry(sub.descriptor, DefaultSubscribeExpiry)
	renewInterval := max(expiry/2, defaultRenewInterval)
	if err := h.sendSubscribe(ctx, sub.key, sub.descriptor, expiry); err != nil && ctx.Err() == nil {
		h.log.Warn().Err(err).
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
			if err := h.sendSubscribe(ctx, sub.key, sub.descriptor, expiry); err != nil && ctx.Err() == nil {
				h.log.Warn().Err(err).
					Stringer("room_id", sub.key.roomID).
					Stringer("event_id", sub.key.eventID).
					Msg("Failed to renew beeper stream subscribe")
			}
		}
	}
}

func (h *Helper) sendSubscribe(ctx context.Context, key streamKey, descriptor *event.BeeperStreamInfo, expiry time.Duration) error {
	client, err := h.requireClient(true)
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
	if descriptor.Encryption != nil {
		payload, err := json.Marshal(map[string]any{
			"device_id": client.DeviceID,
			"expiry_ms": expiry.Milliseconds(),
		})
		if err != nil {
			return err
		}
		encContent, err := encryptLogicalEvent(event.ToDeviceBeeperStreamSubscribe, payload, key.roomID, key.eventID, descriptor.Encryption.Key)
		if err != nil {
			return err
		}
		eventType = event.ToDeviceEncrypted
		content = encContent
	}
	_, err = client.SendToDevice(ctx, eventType, &mautrix.ReqSendToDevice{
		Messages: map[id.UserID]map[id.DeviceID]*event.Content{
			descriptor.UserID: {
				targetDevice: content,
			},
		},
	})
	return err
}

func (h *Helper) handleEncryptedForSubscriber(ctx context.Context, evt *event.Event, sub *subscription) *event.Event {
	if sub.descriptor.Encryption == nil {
		return nil
	}
	normalized := decryptedLogicalEvent(ctx, evt, sub.descriptor.Encryption.Key, event.ToDeviceBeeperStreamUpdate)
	if normalized == nil {
		return nil
	}
	update := normalized.Content.AsBeeperStreamUpdate()
	if update.RoomID != sub.key.roomID || update.EventID != sub.key.eventID {
		return nil
	}
	if normalized.Sender != sub.descriptor.UserID {
		h.log.Warn().
			Stringer("sender", normalized.Sender).
			Stringer("expected_user_id", sub.descriptor.UserID).
			Stringer("room_id", update.RoomID).
			Stringer("event_id", update.EventID).
			Msg("Encrypted beeper stream update from unexpected sender, dropping")
		return nil
	}
	return normalized
}
