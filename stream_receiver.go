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

type BeeperStreamUpdate struct {
	Sender  id.UserID
	RoomID  id.RoomID
	EventID id.EventID
	Content *event.Content
}

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

	lock                    sync.RWMutex
	stopped                 bool
	subscriptions           map[beeperStreamKey]*beeperStreamSubscription
	subscriptionsByStreamID map[string]*beeperStreamSubscription
	wg                      sync.WaitGroup
}

type beeperStreamSubscription struct {
	key        beeperStreamKey
	descriptor *event.BeeperStreamInfo
	cancel     context.CancelFunc
}

func NewBeeperStreamReceiver(client *Client, opts *BeeperStreamReceiverOptions) *BeeperStreamReceiver {
	var optsLogger *zerolog.Logger
	if opts != nil {
		optsLogger = opts.Logger
	}
	receiver := &BeeperStreamReceiver{
		client:                  client,
		log:                     resolveStreamLogger(optsLogger, client, beeperStreamReceiverComponentName),
		defaultExpiry:           DefaultBeeperStreamSubscribeExpiry,
		minimumRenewInterval:    defaultBeeperStreamRenewInterval,
		subscriptions:           make(map[beeperStreamKey]*beeperStreamSubscription),
		subscriptionsByStreamID: make(map[string]*beeperStreamSubscription),
	}
	receiver.applyOptions(opts)
	return receiver
}

// GetOrCreateBeeperStreamReceiver returns the cached stream receiver for this client.
func (cli *Client) GetOrCreateBeeperStreamReceiver(opts *BeeperStreamReceiverOptions) *BeeperStreamReceiver {
	if cli == nil {
		return nil
	}
	cli.beeperStreamReceiverLock.Lock()
	defer cli.beeperStreamReceiverLock.Unlock()
	if cli.beeperStreamReceiver != nil {
		cli.beeperStreamReceiver.applyOptions(opts)
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
	if msg == nil {
		return
	}
	if msg.BeeperStream != nil && evt.RoomID != "" && evt.ID != "" {
		if msg.BeeperStream.ExpiryMS > 0 && evt.Timestamp > 0 {
			expiryTime := time.UnixMilli(evt.Timestamp).Add(
				time.Duration(msg.BeeperStream.ExpiryMS) * time.Millisecond)
			if time.Now().After(expiryTime) {
				return
			}
		}
		if err := r.EnsureSubscription(ctx, evt.RoomID, evt.ID, msg.BeeperStream); err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).
				Stringer("room_id", evt.RoomID).
				Stringer("event_id", evt.ID).
				Msg("Failed to ensure beeper stream subscription")
		}
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
		if content == nil {
			return false
		}
		if content.Algorithm != id.AlgorithmBeeperStreamAESGCM {
			return false
		}
		r.handleEncryptedStreamEvent(ctx, evt, content)
		return true
	default:
		return false
	}
}

func (r *BeeperStreamReceiver) EnsureSubscription(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error {
	if descriptor == nil {
		return nil
	} else if err := validateBeeperStreamDescriptor(descriptor); err != nil {
		return err
	}
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	r.lock.Lock()
	if r.stopped {
		r.lock.Unlock()
		return nil
	}
	if existing := r.subscriptions[key]; existing != nil {
		if BeeperStreamDescriptorEqual(existing.descriptor, descriptor) {
			r.lock.Unlock()
			return nil
		}
		existing.cancel()
		delete(r.subscriptions, key)
		if existing.descriptor != nil && existing.descriptor.Encryption != nil && existing.descriptor.Encryption.StreamID != "" {
			delete(r.subscriptionsByStreamID, existing.descriptor.Encryption.StreamID)
		}
	}
	subscribeCtx := context.Background()
	if ctx != nil {
		subscribeCtx = context.WithoutCancel(ctx)
	}
	subCtx, cancel := context.WithCancel(subscribeCtx)
	sub := &beeperStreamSubscription{
		key:        key,
		descriptor: descriptor,
		cancel:     cancel,
	}
	r.subscriptions[key] = sub
	if descriptor.Encryption != nil && descriptor.Encryption.StreamID != "" {
		r.subscriptionsByStreamID[descriptor.Encryption.StreamID] = sub
	}
	r.lock.Unlock()

	r.wg.Add(1)
	go r.runSubscriptionLoop(subCtx, sub)
	return nil
}

func (r *BeeperStreamReceiver) StopSubscription(roomID id.RoomID, eventID id.EventID) {
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	r.lock.Lock()
	sub := r.subscriptions[key]
	if sub != nil {
		delete(r.subscriptions, key)
		if sub.descriptor != nil && sub.descriptor.Encryption != nil && sub.descriptor.Encryption.StreamID != "" {
			delete(r.subscriptionsByStreamID, sub.descriptor.Encryption.StreamID)
		}
	}
	r.lock.Unlock()
	if sub != nil {
		sub.cancel()
	}
}

func (r *BeeperStreamReceiver) Stop() {
	r.lock.Lock()
	r.stopped = true
	subs := r.subscriptions
	r.subscriptions = make(map[beeperStreamKey]*beeperStreamSubscription)
	r.subscriptionsByStreamID = make(map[string]*beeperStreamSubscription)
	r.lock.Unlock()
	for _, sub := range subs {
		sub.cancel()
	}
	r.wg.Wait()
}

func (r *BeeperStreamReceiver) runSubscriptionLoop(ctx context.Context, sub *beeperStreamSubscription) {
	defer r.wg.Done()
	r.lock.RLock()
	expiry := ResolveBeeperStreamSubscribeExpiry(sub.descriptor, r.defaultExpiry)
	renewInterval := max(expiry/2, r.minimumRenewInterval)
	r.lock.RUnlock()
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
		if descriptor.Encryption.Algorithm != id.AlgorithmBeeperStreamAESGCM {
			return fmt.Errorf("unsupported beeper stream encryption algorithm %q", descriptor.Encryption.Algorithm)
		}
		encrypted, err := EncryptBeeperStreamEvent(eventType, subscribeContent, descriptor.Encryption.StreamID, descriptor.Encryption.Key)
		if err != nil {
			return err
		}
		eventType = event.ToDeviceEncrypted
		content = &event.Content{Parsed: encrypted}
	}
	_, err = client.SendToDevice(ctx, eventType, &ReqSendToDevice{
		Messages: map[id.UserID]map[id.DeviceID]*event.Content{
			descriptor.UserID: {
				id.DeviceID("*"): content,
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
	if update == nil {
		return
	}
	if update.RoomID == "" || update.EventID == "" {
		return
	}
	key := beeperStreamKey{roomID: update.RoomID, eventID: update.EventID}
	r.lock.Lock()
	sub := r.subscriptions[key]
	r.lock.Unlock()
	if sub == nil {
		return
	}
	if sender != sub.descriptor.UserID {
		r.log.Warn().
			Stringer("sender", sender).
			Stringer("expected_user_id", sub.descriptor.UserID).
			Stringer("room_id", update.RoomID).
			Stringer("event_id", update.EventID).
			Msg("Beeper stream update from unexpected sender, dropping")
		return
	}
	r.dispatchUpdate(ctx, sender, update.RoomID, update.EventID, content)
}

func (r *BeeperStreamReceiver) dispatchUpdate(ctx context.Context, sender id.UserID, roomID id.RoomID, eventID id.EventID, content *event.Content) {
	r.lock.RLock()
	onUpdate := r.onUpdate
	r.lock.RUnlock()
	if onUpdate == nil {
		return
	}
	if err := onUpdate(ctx, &BeeperStreamUpdate{
		Sender:  sender,
		RoomID:  roomID,
		EventID: eventID,
		Content: content,
	}); err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).
			Stringer("room_id", roomID).
			Stringer("event_id", eventID).
			Msg("Beeper stream update callback failed")
	}
}

func (r *BeeperStreamReceiver) applyOptions(opts *BeeperStreamReceiverOptions) {
	if r == nil || opts == nil {
		return
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if opts.Logger != nil {
		r.log = opts.Logger.With().Str("component", beeperStreamReceiverComponentName).Logger()
	}
	if opts.DefaultExpiry > 0 {
		r.defaultExpiry = opts.DefaultExpiry
	}
	if opts.MinimumRenewInterval > 0 {
		r.minimumRenewInterval = opts.MinimumRenewInterval
	}
	if opts.OnUpdate != nil {
		r.onUpdate = opts.OnUpdate
	}
}

func (r *BeeperStreamReceiver) handleEncryptedStreamEvent(ctx context.Context, evt *event.Event, content *event.EncryptedEventContent) {
	if content.StreamID == "" {
		return
	}
	r.lock.Lock()
	sub := r.subscriptionsByStreamID[content.StreamID]
	r.lock.Unlock()
	if sub == nil {
		return
	}
	logicalType, parsedContent, err := DecryptBeeperStreamEvent(content, sub.descriptor.Encryption.Key)
	if err != nil {
		return
	}
	if logicalType != event.ToDeviceBeeperStreamUpdate {
		return
	}
	update := parsedContent.AsBeeperStreamUpdate()
	if update.RoomID != sub.key.roomID || update.EventID != sub.key.eventID {
		return
	}
	if evt.Sender != sub.descriptor.UserID {
		r.log.Warn().
			Stringer("sender", evt.Sender).
			Stringer("expected_user_id", sub.descriptor.UserID).
			Stringer("room_id", update.RoomID).
			Stringer("event_id", update.EventID).
			Msg("Encrypted beeper stream update from unexpected sender, dropping")
		return
	}
	r.dispatchUpdate(ctx, evt.Sender, update.RoomID, update.EventID, parsedContent)
}

func (r *BeeperStreamReceiver) requireClient() (*Client, error) {
	if r == nil {
		return requireStreamReceiverClient(nil, "receiver")
	}
	return requireStreamReceiverClient(r.client, "receiver")
}
