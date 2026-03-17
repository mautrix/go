// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"context"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// BeeperStreamTransport is a low-level interface for managing beeper streams,
// where the caller controls the room/event IDs explicitly (e.g. ai-bridge).
type BeeperStreamTransport interface {
	BuildDescriptor(ctx context.Context, roomID id.RoomID, streamType string) (*event.BeeperStreamInfo, error)
	Start(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error
	Publish(ctx context.Context, roomID id.RoomID, eventID id.EventID, content map[string]any) error
	Finish(ctx context.Context, roomID id.RoomID, eventID id.EventID) error
}

var _ BeeperStreamTransport = (*BeeperStreamSender)(nil)

// BeeperStreamSenderOptions configures a [BeeperStreamSender].
type BeeperStreamSenderOptions struct {
	Logger              *zerolog.Logger
	IsEncrypted         func(context.Context, id.RoomID) (bool, error)
	AuthorizeSubscriber func(context.Context, *BeeperStreamSubscribeRequest) bool
}

// BeeperStreamSubscribeRequest describes a pending Beeper stream subscribe request.
type BeeperStreamSubscribeRequest struct {
	RoomID   id.RoomID
	EventID  id.EventID
	UserID   id.UserID
	DeviceID id.DeviceID
	Expiry   time.Duration
}

// BeeperStreamSender manages outgoing Beeper stream subscriptions and updates for a client.
type BeeperStreamSender struct {
	client *Client
	log    zerolog.Logger

	authorizeSubscriber func(context.Context, *BeeperStreamSubscribeRequest) bool
	isEncrypted         func(context.Context, id.RoomID) (bool, error)
	now                 func() time.Time

	lock              sync.RWMutex
	streams           map[beeperStreamKey]*beeperStreamState
	streamsByStreamID map[id.StreamID]*beeperStreamState

	pendingLock      sync.Mutex
	pendingSubscribe []pendingSubscribeEvent
}

// NewBeeperStreamSender creates a new [BeeperStreamSender] bound to the given client.
func NewBeeperStreamSender(client *Client, opts *BeeperStreamSenderOptions) *BeeperStreamSender {
	var optsLogger *zerolog.Logger
	if opts != nil {
		optsLogger = opts.Logger
	}
	sender := &BeeperStreamSender{
		log:               resolveStreamLogger(optsLogger, client, beeperStreamComponentName),
		client:            client,
		now:               time.Now,
		streams:           make(map[beeperStreamKey]*beeperStreamState),
		streamsByStreamID: make(map[id.StreamID]*beeperStreamState),
	}
	sender.applyOptions(opts)
	if sender.isEncrypted == nil {
		sender.isEncrypted = sender.defaultIsEncrypted
	}
	return sender
}

// GetOrCreateBeeperStreamSender returns the cached stream sender for this client.
func (cli *Client) GetOrCreateBeeperStreamSender(opts *BeeperStreamSenderOptions) *BeeperStreamSender {
	if cli == nil {
		return nil
	}
	cli.beeperStreamSenderLock.Lock()
	defer cli.beeperStreamSenderLock.Unlock()
	if cli.beeperStreamSender != nil {
		cli.beeperStreamSender.applyOptions(opts)
		return cli.beeperStreamSender
	}
	cli.beeperStreamSender = NewBeeperStreamSender(cli, opts)
	cli.AddToDeviceInterceptor(cli.beeperStreamSender.HandleToDeviceEvent)
	return cli.beeperStreamSender
}

func (s *BeeperStreamSender) defaultIsEncrypted(ctx context.Context, roomID id.RoomID) (bool, error) {
	if s.client == nil || s.client.StateStore == nil {
		return false, nil
	}
	return s.client.StateStore.IsEncrypted(ctx, roomID)
}

func (s *BeeperStreamSender) applyOptions(opts *BeeperStreamSenderOptions) {
	if s == nil || opts == nil {
		return
	}
	if opts.Logger != nil {
		s.log = opts.Logger.With().Str("component", beeperStreamComponentName).Logger()
	}
	if opts.IsEncrypted != nil {
		s.isEncrypted = opts.IsEncrypted
	} else if s.isEncrypted == nil {
		s.isEncrypted = s.defaultIsEncrypted
	}
	if opts.AuthorizeSubscriber != nil {
		s.authorizeSubscriber = opts.AuthorizeSubscriber
	}
}

func (s *BeeperStreamSender) HandleToDeviceEvent(ctx context.Context, evt *event.Event) bool {
	if s == nil || evt == nil {
		return false
	}
	if err := prepareToDeviceEvent(evt); err != nil {
		return false
	}
	switch evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		return s.handleSubscribeEvent(ctx, evt)
	case event.ToDeviceEncrypted:
		return s.handleEncryptedEvent(ctx, evt)
	default:
		return false
	}
}

func (s *BeeperStreamSender) handleSubscribeEvent(ctx context.Context, evt *event.Event) bool {
	if s.isForDifferentUser(evt) {
		return true
	}
	subscribe := evt.Content.AsBeeperStreamSubscribe()
	if subscribe.RoomID == "" || subscribe.EventID == "" {
		return true
	}
	if s.handleSubscribe(ctx, evt.Sender, subscribe) {
		return true
	}
	s.queuePendingSubscribe(ctx, evt)
	return true
}

func (s *BeeperStreamSender) handleEncryptedEvent(ctx context.Context, evt *event.Event) bool {
	content := evt.Content.AsEncrypted()
	if content.Algorithm != id.AlgorithmBeeperStreamAESGCM {
		return false
	} else if s.isForDifferentUser(evt) {
		return true
	}
	log := zerolog.Ctx(ctx).With().
		Str("sender", evt.Sender.String()).
		Str("stream_id", content.StreamID.String()).
		Logger()
	ctx = log.WithContext(ctx)
	if content.StreamID == "" {
		log.Debug().Msg("Custom encrypted to-device event missing stream_id, dropping")
		return true
	}
	if !s.tryEncryptedSubscribeCandidates(ctx, evt, content) {
		log.Debug().Msg("Custom encrypted to-device event doesn't match an active beeper stream, queueing as pending")
		s.queuePendingSubscribe(ctx, evt)
	}
	return true
}

func (s *BeeperStreamSender) tryEncryptedSubscribeCandidates(ctx context.Context, evt *event.Event, content *event.EncryptedEventContent) bool {
	s.lock.RLock()
	state := s.streamsByStreamID[content.StreamID]
	s.lock.RUnlock()
	if state == nil {
		return false
	}
	return s.tryDecryptAndSubscribe(ctx, evt, content, state)
}

func (s *BeeperStreamSender) isForDifferentUser(evt *event.Event) bool {
	if s.client == nil {
		return true
	}
	if evt == nil {
		return false
	}
	return evt.ToUserID != "" && evt.ToUserID != s.client.UserID
}

func (s *BeeperStreamSender) tryDecryptAndSubscribe(ctx context.Context, evt *event.Event, content *event.EncryptedEventContent, state *beeperStreamState) bool {
	log := zerolog.Ctx(ctx).With().
		Str("stream_room_id", state.key.roomID.String()).
		Str("stream_event_id", state.key.eventID.String()).
		Logger()
	if state.gcm == nil {
		return false
	}
	payload, err := decryptStreamPayload(content, state.gcm)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to decrypt custom encrypted subscribe")
		return false
	}
	if payload.Type != event.ToDeviceBeeperStreamSubscribe.Type {
		log.Debug().Str("payload_type", payload.Type).Msg("Ignoring decrypted custom beeper stream payload with unexpected type")
		return false
	}
	var subscribe event.BeeperStreamSubscribeEventContent
	if err = json.Unmarshal(payload.Content, &subscribe); err != nil {
		log.Debug().Err(err).RawJSON("payload_content", payload.Content).Msg("Failed to unmarshal decrypted custom subscribe payload")
		return false
	}
	if subscribe.RoomID != state.key.roomID || subscribe.EventID != state.key.eventID {
		log.Debug().
			Str("subscribe_room_id", subscribe.RoomID.String()).
			Str("subscribe_event_id", subscribe.EventID.String()).
			Msg("Decrypted custom subscribe payload did not match beeper stream candidate")
		return false
	}
	return s.handleSubscribe(ctx, evt.Sender, &subscribe)
}

func (s *BeeperStreamSender) handleSubscribe(ctx context.Context, sender id.UserID, subscribe *event.BeeperStreamSubscribeEventContent) bool {
	if subscribe == nil {
		return false
	}
	key := beeperStreamKey{roomID: subscribe.RoomID, eventID: subscribe.EventID}
	s.lock.Lock()
	state := s.streams[key]
	if state == nil {
		s.lock.Unlock()
		return false
	} else if state.finished {
		s.lock.Unlock()
		return true
	}
	authFunc := s.authorizeSubscriber
	authReq := &BeeperStreamSubscribeRequest{
		RoomID:   subscribe.RoomID,
		EventID:  subscribe.EventID,
		UserID:   sender,
		DeviceID: subscribe.DeviceID,
		Expiry:   time.Duration(subscribe.ExpiryMS) * time.Millisecond,
	}
	if authFunc != nil {
		s.lock.Unlock()
		if !authFunc(ctx, authReq) {
			return true
		}
		s.lock.Lock()
		state = s.streams[key]
		if state == nil || state.finished {
			s.lock.Unlock()
			return true
		}
	}
	expiry := resolveBeeperStreamSubscribeExpiry(state.descriptor, authReq.Expiry)
	sub := beeperStreamSubscriber{userID: sender, deviceID: subscribe.DeviceID}
	state.subscribers[sub] = s.now().Add(expiry)
	desc := state.descriptor
	gcm := state.gcm
	updates := slices.Clone(state.updates)
	s.lock.Unlock()

	for _, update := range updates {
		if err := s.sendUpdateToSubscribers(ctx, desc, gcm, update, []beeperStreamSubscriber{sub}); err != nil {
			s.lock.Lock()
			state = s.streams[key]
			if state != nil {
				delete(state.subscribers, sub)
			}
			s.lock.Unlock()
			return true
		}
	}
	return true
}

func (s *BeeperStreamSender) recordUpdate(roomID id.RoomID, eventID id.EventID, content map[string]any) (desc *event.BeeperStreamInfo, gcm cipher.AEAD, update *event.Content, subscribers []beeperStreamSubscriber, err error) {
	update, err = newStreamUpdateContent(roomID, eventID, content)
	if err != nil {
		return
	}
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	s.lock.Lock()
	defer s.lock.Unlock()
	state := s.streams[key]
	if state == nil {
		err = fmt.Errorf("beeper stream %s/%s not found", roomID, eventID)
		return
	} else if state.finished {
		err = fmt.Errorf("beeper stream %s/%s already finished", roomID, eventID)
		return
	}
	state.updates = append(state.updates, update)
	if len(state.updates) > maxUpdatesPerStream {
		state.updates = state.updates[len(state.updates)-maxUpdatesPerStream:]
	}
	desc = state.descriptor
	gcm = state.gcm
	subscribers = state.activeSubscribers(s.now())
	return
}

func (s *BeeperStreamSender) sendUpdateToSubscribers(ctx context.Context, descriptor *event.BeeperStreamInfo, gcm cipher.AEAD, update *event.Content, subscribers []beeperStreamSubscriber) error {
	if len(subscribers) == 0 {
		return nil
	}
	client, err := s.requireClient()
	if err != nil {
		return err
	}
	eventType := event.ToDeviceBeeperStreamUpdate
	content := update
	if descriptor != nil && descriptor.Encryption != nil && gcm != nil {
		encrypted, encErr := encryptStreamPayload(eventType, update, descriptor.Encryption.StreamID, gcm)
		if encErr != nil {
			return encErr
		}
		eventType = event.ToDeviceEncrypted
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

func (s *BeeperStreamSender) requireClient() (*Client, error) {
	if s == nil {
		return requireStreamSenderClient(nil, "sender")
	}
	return requireStreamSenderClient(s.client, "sender")
}

func (s *BeeperStreamSender) queuePendingSubscribe(ctx context.Context, evt *event.Event) {
	if evt == nil {
		return
	}
	now := s.now()
	s.pendingLock.Lock()
	defer s.pendingLock.Unlock()
	s.pendingSubscribe = append(s.pendingSubscribe, pendingSubscribeEvent{
		evt:        evt,
		receivedAt: now,
	})
	if len(s.pendingSubscribe) > maxPendingSubscribes {
		s.pendingSubscribe = s.pendingSubscribe[len(s.pendingSubscribe)-maxPendingSubscribes:]
	}
	zerolog.Ctx(ctx).Debug().
		Int("pending_subscribes", len(s.pendingSubscribe)).
		Str("sender", evt.Sender.String()).
		Str("event_type", evt.Type.Type).
		Msg("Queued subscribe for possible future beeper stream registration")
}

func (s *BeeperStreamSender) replayPendingSubscribes(ctx context.Context) {
	now := s.now()
	s.pendingLock.Lock()
	if len(s.pendingSubscribe) == 0 {
		s.pendingLock.Unlock()
		return
	}
	pending := slices.Clone(s.pendingSubscribe)
	s.pendingLock.Unlock()
	consumed := make(map[*event.Event]struct{})
	for _, candidate := range pending {
		if candidate.evt == nil || now.Sub(candidate.receivedAt) > pendingSubscribeTTL {
			continue
		}
		if s.tryPendingSubscribe(ctx, candidate.evt) {
			consumed[candidate.evt] = struct{}{}
		}
	}
	if len(consumed) == 0 {
		return
	}
	s.pendingLock.Lock()
	defer s.pendingLock.Unlock()
	var filtered []pendingSubscribeEvent
	for _, candidate := range s.pendingSubscribe {
		if candidate.evt == nil || now.Sub(candidate.receivedAt) > pendingSubscribeTTL {
			continue
		}
		if _, ok := consumed[candidate.evt]; ok {
			continue
		}
		filtered = append(filtered, candidate)
	}
	s.pendingSubscribe = filtered
}

func (s *BeeperStreamSender) tryPendingSubscribe(ctx context.Context, evt *event.Event) bool {
	if evt == nil {
		return false
	}
	switch evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		subscribe := evt.Content.AsBeeperStreamSubscribe()
		if subscribe.RoomID == "" || subscribe.EventID == "" {
			return false
		}
		return s.handleSubscribe(ctx, evt.Sender, subscribe)
	case event.ToDeviceEncrypted:
		content, ok := evt.Content.Parsed.(*event.EncryptedEventContent)
		if !ok || content.Algorithm != id.AlgorithmBeeperStreamAESGCM {
			return false
		}
		return s.tryEncryptedSubscribeCandidates(ctx, evt, content)
	}
	return false
}

func (state *beeperStreamState) activeSubscribers(now time.Time) []beeperStreamSubscriber {
	var active []beeperStreamSubscriber
	doEvict := now.Sub(state.lastEviction) >= streamCleanupGrace
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

func (s *BeeperStreamSender) activateStream(ctx context.Context, roomID id.RoomID, eventID id.EventID, info *event.BeeperStreamInfo) error {
	if err := validateBeeperStreamDescriptor(info); err != nil {
		return err
	}
	cloned := *info
	descriptor := &cloned
	if info.Encryption != nil {
		enc := *info.Encryption
		descriptor.Encryption = &enc
	}
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	s.lock.Lock()
	if _, exists := s.streams[key]; exists {
		s.lock.Unlock()
		return fmt.Errorf("beeper stream %s/%s already started", roomID, eventID)
	}
	if descriptor.Encryption != nil {
		if _, exists := s.streamsByStreamID[descriptor.Encryption.StreamID]; exists {
			s.lock.Unlock()
			return fmt.Errorf("beeper stream %s/%s has duplicate stream_id", roomID, eventID)
		}
	}
	state := &beeperStreamState{
		key:         key,
		descriptor:  descriptor,
		subscribers: make(map[beeperStreamSubscriber]time.Time),
	}
	if descriptor.Encryption != nil {
		gcm, err := newStreamGCM(descriptor.Encryption.Key)
		if err != nil {
			s.lock.Unlock()
			return fmt.Errorf("failed to initialize beeper stream cipher: %w", err)
		}
		state.gcm = gcm
	}
	s.streams[key] = state
	if descriptor.Encryption != nil {
		s.streamsByStreamID[descriptor.Encryption.StreamID] = state
	}
	s.lock.Unlock()
	s.replayPendingSubscribes(ctx)
	return nil
}

// BuildDescriptor implements BeeperStreamTransport.
func (s *BeeperStreamSender) BuildDescriptor(ctx context.Context, roomID id.RoomID, streamType string) (*event.BeeperStreamInfo, error) {
	if s == nil {
		return nil, fmt.Errorf("beeper stream sender is nil")
	} else if roomID == "" || streamType == "" {
		return nil, fmt.Errorf("missing beeper stream descriptor request fields")
	}
	client, err := s.requireClient()
	if err != nil {
		return nil, err
	}
	info := &event.BeeperStreamInfo{
		UserID:   client.UserID,
		Type:     streamType,
		ExpiryMS: DefaultBeeperStreamDescriptorExpiry.Milliseconds(),
	}
	isEncrypted, err := s.isEncrypted(ctx, roomID)
	if err != nil {
		return nil, err
	}
	if isEncrypted {
		info.Encryption = &event.BeeperStreamEncryptionInfo{
			Algorithm: id.AlgorithmBeeperStreamAESGCM,
			Key:       makeStreamKey(),
			StreamID:  makeStreamID(),
		}
	}
	return info, nil
}

// Start implements BeeperStreamTransport by activating the stream for the given event.
func (s *BeeperStreamSender) Start(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error {
	return s.activateStream(ctx, roomID, eventID, descriptor)
}

// Publish implements BeeperStreamTransport by recording an update and sending it to subscribers.
func (s *BeeperStreamSender) Publish(ctx context.Context, roomID id.RoomID, eventID id.EventID, content map[string]any) error {
	desc, gcm, update, subscribers, err := s.recordUpdate(roomID, eventID, content)
	if err != nil {
		return err
	}
	return s.sendUpdateToSubscribers(ctx, desc, gcm, update, subscribers)
}

// Finish implements BeeperStreamTransport by closing the stream identified by roomID/eventID.
func (s *BeeperStreamSender) Finish(_ context.Context, roomID id.RoomID, eventID id.EventID) error {
	key := beeperStreamKey{roomID: roomID, eventID: eventID}
	s.lock.Lock()
	defer s.lock.Unlock()
	state := s.streams[key]
	if state == nil {
		return fmt.Errorf("beeper stream %s/%s not found", roomID, eventID)
	}
	state.finished = true
	state.subscribers = nil
	if state.descriptor.Encryption != nil && state.descriptor.Encryption.StreamID != "" {
		delete(s.streamsByStreamID, state.descriptor.Encryption.StreamID)
	}
	if state.cleanup != nil {
		state.cleanup.Stop()
	}
	state.cleanup = time.AfterFunc(streamCleanupGrace, func() {
		s.lock.Lock()
		defer s.lock.Unlock()
		delete(s.streams, key)
	})
	return nil
}
