// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type BeeperStreamReceiverOptions struct {
	Logger               *zerolog.Logger
	DefaultExpiry        time.Duration
	MinimumRenewInterval time.Duration
	OnUpdate             func(context.Context, *BeeperStreamUpdate) error
}

type BeeperStreamReceiver struct {
	client *Client
	log    zerolog.Logger

	defaultExpiry        time.Duration
	minimumRenewInterval time.Duration
	onUpdate             func(context.Context, *BeeperStreamUpdate) error

	lock          sync.Mutex
	subscriptions map[beeperStreamKey]*beeperStreamSubscription
}

type beeperStreamSubscription struct {
	key        beeperStreamKey
	descriptor *event.BeeperStreamInfo
	cancel     context.CancelFunc
}

func NewBeeperStreamReceiver(client *Client, opts *BeeperStreamReceiverOptions) *BeeperStreamReceiver {
	var log zerolog.Logger
	switch {
	case opts != nil && opts.Logger != nil:
		log = opts.Logger.With().Str("component", defaultBeeperStreamComponent+"_receiver").Logger()
	case client != nil:
		log = client.Log.With().Str("component", defaultBeeperStreamComponent+"_receiver").Logger()
	default:
		log = zerolog.Nop()
	}
	receiver := &BeeperStreamReceiver{
		client:               client,
		log:                  log,
		defaultExpiry:        DefaultBeeperStreamExpiry,
		minimumRenewInterval: defaultBeeperRenewInterval,
		subscriptions:        make(map[beeperStreamKey]*beeperStreamSubscription),
	}
	if opts != nil {
		if opts.DefaultExpiry > 0 {
			receiver.defaultExpiry = opts.DefaultExpiry
		}
		if opts.MinimumRenewInterval > 0 {
			receiver.minimumRenewInterval = opts.MinimumRenewInterval
		}
		receiver.onUpdate = opts.OnUpdate
	}
	return receiver
}

func (cli *Client) GetOrCreateBeeperStreamReceiver(opts *BeeperStreamReceiverOptions) *BeeperStreamReceiver {
	if cli == nil {
		return nil
	}
	cli.beeperStreamReceiverLock.Lock()
	defer cli.beeperStreamReceiverLock.Unlock()
	if cli.beeperStreamReceiver != nil {
		return cli.beeperStreamReceiver
	}
	cli.beeperStreamReceiver = NewBeeperStreamReceiver(cli, opts)
	cli.AddToDeviceInterceptor(cli.beeperStreamReceiver.HandleToDeviceEvent)
	return cli.beeperStreamReceiver
}

func (r *BeeperStreamReceiver) HandleTimelineEvent(ctx context.Context, evt *event.Event) {
	if r == nil || evt == nil || evt.Type != event.EventMessage {
		return
	}
	if evt.Content.Parsed == nil {
		if err := evt.Content.ParseRaw(evt.Type); err != nil {
			return
		}
	}
	msg := evt.Content.AsMessage()
	if msg.BeeperStream != nil && evt.RoomID != "" && evt.ID != "" {
		_ = r.EnsureSubscription(ctx, evt.RoomID, evt.ID, msg.BeeperStream)
		return
	}
	if msg.RelatesTo != nil && msg.RelatesTo.Type == event.RelReplace && msg.RelatesTo.EventID != "" {
		if msg.NewContent == nil || msg.NewContent.BeeperStream == nil {
			r.StopSubscription(evt.RoomID, msg.RelatesTo.EventID)
		}
	}
}

func (r *BeeperStreamReceiver) HandleToDeviceEvent(ctx context.Context, evt *event.Event) bool {
	if r == nil || evt == nil {
		return false
	}
	if evt.Content.Parsed == nil {
		_ = evt.Content.ParseRaw(evt.Type)
	}
	switch evt.Type {
	case event.ToDeviceBeeperStreamUpdate:
		r.handleStreamUpdateEvent(ctx, evt.Sender, &evt.Content)
		return true
	case event.ToDeviceEncrypted:
		content := evt.Content.AsEncrypted()
		if content.Algorithm != id.AlgorithmBeeperStreamAESGCM {
			return false
		}
		r.handleEncryptedStreamEvent(ctx, evt)
		return true
	default:
		return false
	}
}

func (r *BeeperStreamReceiver) EnsureSubscription(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error {
	if descriptor == nil {
		return nil
	}
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	r.lock.Lock()
	if existing := r.subscriptions[key]; existing != nil {
		if BeeperStreamDescriptorEqual(existing.descriptor, descriptor) {
			r.lock.Unlock()
			return nil
		}
		existing.cancel()
		delete(r.subscriptions, key)
	}
	subCtx, cancel := context.WithCancel(context.Background())
	sub := &beeperStreamSubscription{
		key:        key,
		descriptor: descriptor,
		cancel:     cancel,
	}
	r.subscriptions[key] = sub
	r.lock.Unlock()

	go r.runSubscriptionLoop(withContextLogger(subCtx, zerolog.Ctx(ctx)), sub)
	return nil
}

func (r *BeeperStreamReceiver) StopSubscription(roomID id.RoomID, eventID id.EventID) {
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	r.lock.Lock()
	sub := r.subscriptions[key]
	if sub != nil {
		delete(r.subscriptions, key)
	}
	r.lock.Unlock()
	if sub != nil {
		sub.cancel()
	}
}

func (r *BeeperStreamReceiver) runSubscriptionLoop(ctx context.Context, sub *beeperStreamSubscription) {
	expiry := ResolveBeeperStreamSubscribeExpiry(sub.descriptor, r.defaultExpiry)
	renewInterval := expiry / 2
	if renewInterval < r.minimumRenewInterval {
		renewInterval = r.minimumRenewInterval
	}
	if err := r.sendStreamSubscribe(ctx, sub.key, sub.descriptor, expiry); err != nil && !errors.Is(err, context.Canceled) {
		r.log.Warn().Err(err).
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
			if err := r.sendStreamSubscribe(ctx, sub.key, sub.descriptor, expiry); err != nil && !errors.Is(err, context.Canceled) {
				r.log.Warn().Err(err).
					Stringer("room_id", sub.key.roomID).
					Stringer("event_id", sub.key.eventID).
					Msg("Failed to renew beeper stream subscribe")
			}
		}
	}
}

func (r *BeeperStreamReceiver) sendStreamSubscribe(ctx context.Context, key beeperStreamKey, descriptor *event.BeeperStreamInfo, expiry time.Duration) error {
	if descriptor == nil {
		return nil
	}
	client, err := r.requireClient()
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
	if descriptor.Encryption != nil {
		encrypted, err := EncryptBeeperStreamEvent(eventType, subscribeContent, key.roomID, key.eventID, descriptor.Encryption.Key)
		if err != nil {
			return err
		}
		eventType = event.ToDeviceEncrypted
		content = &event.Content{Parsed: encrypted}
	}
	_, err = client.SendToDevice(ctx, eventType, &ReqSendToDevice{
		Messages: map[id.UserID]map[id.DeviceID]*event.Content{
			descriptor.UserID: {
				descriptor.DeviceID: content,
			},
		},
	})
	return err
}

func (r *BeeperStreamReceiver) handleStreamUpdateEvent(ctx context.Context, sender id.UserID, content *event.Content) {
	if content == nil {
		return
	}
	update := content.AsBeeperStreamUpdate()
	if update.RoomID == "" || update.EventID == "" {
		return
	}
	if r.onUpdate != nil {
		if err := r.onUpdate(ctx, &BeeperStreamUpdate{
			Sender:  sender,
			RoomID:  update.RoomID,
			EventID: update.EventID,
			Content: content,
		}); err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).
				Stringer("room_id", update.RoomID).
				Stringer("event_id", update.EventID).
				Msg("Beeper stream update callback failed")
		}
	}
}

func (r *BeeperStreamReceiver) handleEncryptedStreamEvent(ctx context.Context, evt *event.Event) {
	content := evt.Content.AsEncrypted()
	if content == nil {
		return
	}
	r.lock.Lock()
	subs := make([]*beeperStreamSubscription, 0, len(r.subscriptions))
	if content.RoomID != "" && content.EventID != "" {
		if sub := r.subscriptions[beeperStreamKey{roomID: content.RoomID, eventID: content.EventID}]; sub != nil &&
			sub.descriptor != nil && sub.descriptor.Encryption != nil {
			subs = append(subs, sub)
		}
	} else {
		for _, sub := range r.subscriptions {
			if sub.descriptor == nil || sub.descriptor.Encryption == nil {
				continue
			}
			subs = append(subs, sub)
		}
	}
	r.lock.Unlock()

	for _, sub := range subs {
		logicalType, parsedContent, err := DecryptBeeperStreamEvent(content, sub.descriptor.Encryption.Key)
		if err != nil {
			continue
		}
		if logicalType != event.ToDeviceBeeperStreamUpdate {
			continue
		}
		update := parsedContent.AsBeeperStreamUpdate()
		if update.RoomID != sub.key.roomID || update.EventID != sub.key.eventID {
			continue
		}
		r.handleStreamUpdateEvent(ctx, evt.Sender, parsedContent)
		return
	}
}

func (r *BeeperStreamReceiver) requireClient() (*Client, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("beeper stream receiver doesn't have a client")
	} else if r.client.UserID == "" {
		return nil, fmt.Errorf("beeper stream receiver client isn't logged in")
	} else if r.client.DeviceID == "" {
		return nil, fmt.Errorf("beeper stream receiver client doesn't have a device ID")
	}
	return r.client, nil
}

func withContextLogger(ctx context.Context, log *zerolog.Logger) context.Context {
	if log == nil {
		return ctx
	}
	return log.WithContext(ctx)
}
