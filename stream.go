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
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/random"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	DefaultBeeperStreamDescriptorExpiry = 30 * time.Minute
	DefaultBeeperStreamSubscribeExpiry  = 5 * time.Minute
	defaultBeeperStreamRenewInterval    = 30 * time.Second
	streamCleanupGrace                  = 30 * time.Second
	pendingSubscribeTTL                 = 5 * time.Second
	maxPendingSubscribes                = 64
	maxUpdatesPerStream                 = 1024
	beeperStreamComponentName           = "beeper_stream"
)

type BeeperStreamSenderOptions struct {
	Logger      *zerolog.Logger
	IsEncrypted func(context.Context, id.RoomID) (bool, error)
}

type BeeperStreamPublisherOptions struct {
	AuthorizeSubscriber func(context.Context, *BeeperStreamSubscribeRequest) bool
}

// BeeperStreamTransport is an abstract entry point for managing the stream lifecycle.
// Obtain one via BeeperStreamPublisher.NewTransport().
type BeeperStreamTransport interface {
	BuildDescriptor(ctx context.Context, roomID id.RoomID, streamType string) (*event.BeeperStreamInfo, error)
	Start(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error
	Publish(ctx context.Context, roomID id.RoomID, eventID id.EventID, content map[string]any) error
	Finish(ctx context.Context, roomID id.RoomID, eventID id.EventID) error
}

type BeeperStreamSubscribeRequest struct {
	RoomID   id.RoomID
	EventID  id.EventID
	UserID   id.UserID
	DeviceID id.DeviceID
	Expiry   time.Duration
}

type BeeperStreamUpdate struct {
	Sender  id.UserID
	RoomID  id.RoomID
	EventID id.EventID
	Content *event.Content
}

type BeeperStreamSender struct {
	client *Client
	log    zerolog.Logger

	isEncrypted func(context.Context, id.RoomID) (bool, error)
	now         func() time.Time

	lock              sync.RWMutex
	streams           map[beeperStreamKey]*beeperStreamState
	streamsByStreamID map[string]*beeperStreamState

	pendingLock      sync.Mutex
	pendingSubscribe []pendingSubscribeEvent
}

type BeeperStreamPublisher struct {
	sender              *BeeperStreamSender
	authorizeSubscriber func(context.Context, *BeeperStreamSubscribeRequest) bool
}

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

	authorizeSubscriber func(context.Context, *BeeperStreamSubscribeRequest) bool

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
		streamsByStreamID: make(map[string]*beeperStreamState),
	}
	if opts != nil && opts.IsEncrypted != nil {
		sender.isEncrypted = opts.IsEncrypted
	} else {
		sender.isEncrypted = sender.defaultIsEncrypted
	}
	return sender
}

// GetOrCreateBeeperStreamSender returns the cached stream sender for this client.
//
// The first call initializes the singleton with the provided options. Later calls
// ignore opts and return the existing sender.
func (cli *Client) GetOrCreateBeeperStreamSender(opts *BeeperStreamSenderOptions) *BeeperStreamSender {
	if cli == nil {
		return nil
	}
	cli.beeperStreamSenderLock.Lock()
	defer cli.beeperStreamSenderLock.Unlock()
	if cli.beeperStreamSender != nil {
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

func (s *BeeperStreamSender) NewPublisher(opts *BeeperStreamPublisherOptions) *BeeperStreamPublisher {
	publisher := &BeeperStreamPublisher{sender: s}
	if opts != nil {
		publisher.authorizeSubscriber = opts.AuthorizeSubscriber
	}
	return publisher
}

func (p *BeeperStreamPublisher) requireSender() (*BeeperStreamSender, error) {
	if p == nil || p.sender == nil {
		return nil, fmt.Errorf("beeper stream sender is nil")
	}
	return p.sender, nil
}

func (p *BeeperStreamPublisher) publish(ctx context.Context, roomID id.RoomID, eventID id.EventID, content map[string]any) error {
	s, err := p.requireSender()
	if err != nil {
		return err
	} else if roomID == "" || eventID == "" {
		return fmt.Errorf("missing beeper stream identifiers")
	}
	desc, gcm, update, subscribers, err := s.recordUpdate(roomID, eventID, content)
	if err != nil {
		return err
	}
	return s.sendUpdateToSubscribers(ctx, desc, gcm, update, subscribers)
}

func (p *BeeperStreamPublisher) finish(_ context.Context, roomID id.RoomID, eventID id.EventID) error {
	s, err := p.requireSender()
	if err != nil {
		return err
	} else if roomID == "" || eventID == "" {
		return fmt.Errorf("missing beeper stream identifiers")
	}
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

func (s *BeeperStreamSender) HandleToDeviceEvent(ctx context.Context, evt *event.Event) bool {
	if s == nil || evt == nil {
		return false
	}
	if evt.Content.Parsed == nil {
		_ = evt.Content.ParseRaw(evt.Type)
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
	if s.isForDifferentDevice(evt) {
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
	} else if s.isForDifferentDevice(evt) {
		return true
	}
	log := zerolog.Ctx(ctx).With().
		Str("sender", evt.Sender.String()).
		Str("to_device_id", evt.ToDeviceID.String()).
		Str("stream_id", content.StreamID).
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
	for _, state := range s.collectEncryptedCandidates(content) {
		if s.tryDecryptAndSubscribe(ctx, evt, content, state) {
			return true
		}
	}
	return false
}

func (s *BeeperStreamSender) collectEncryptedCandidates(content *event.EncryptedEventContent) []*beeperStreamState {
	if content.StreamID == "" {
		return nil
	}
	s.lock.RLock()
	defer s.lock.RUnlock()
	if state, ok := s.streamsByStreamID[content.StreamID]; ok {
		return []*beeperStreamState{state}
	}
	return nil
}

func (s *BeeperStreamSender) isForDifferentDevice(evt *event.Event) bool {
	if evt == nil || s.client == nil {
		return s.client == nil
	}
	if evt.ToUserID != "" && evt.ToUserID != s.client.UserID {
		return true
	}
	return evt.ToDeviceID != "" && s.client.DeviceID != "" && evt.ToDeviceID != s.client.DeviceID
}

func (s *BeeperStreamSender) tryDecryptAndSubscribe(ctx context.Context, evt *event.Event, content *event.EncryptedEventContent, state *beeperStreamState) bool {
	log := zerolog.Ctx(ctx).With().
		Str("stream_room_id", state.key.roomID.String()).
		Str("stream_event_id", state.key.eventID.String()).
		Logger()
	gcm, ok := state.getGCM()
	if !ok {
		return false
	}
	payload, err := decryptStreamPayload(content, gcm)
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
	authFunc := state.authorizeSubscriber
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
	expiry := ResolveBeeperStreamSubscribeExpiry(state.descriptor, authReq.Expiry)
	sub := beeperStreamSubscriber{userID: sender, deviceID: subscribe.DeviceID}
	state.subscribers[sub] = s.now().Add(expiry)
	desc := state.descriptor
	gcm, _ := state.getGCM()
	updates := append([]*event.Content(nil), state.updates...)
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
	gcm, _ = state.getGCM()
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
	eventType, content, err := makeToDeviceContent(descriptor, gcm, event.ToDeviceBeeperStreamUpdate, update)
	if err != nil {
		return err
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

// requireStreamClient validates that client is non-nil, logged in, and has a device ID.
// role is used in error messages (e.g. "sender", "receiver").
func requireStreamClient(client *Client, role string) (*Client, error) {
	if client == nil {
		return nil, fmt.Errorf("beeper stream %s doesn't have a client", role)
	} else if client.UserID == "" {
		return nil, fmt.Errorf("beeper stream %s client isn't logged in", role)
	} else if client.DeviceID == "" {
		return nil, fmt.Errorf("beeper stream %s client doesn't have a device ID", role)
	}
	return client, nil
}

// resolveStreamLogger resolves a logger from opts (if non-nil), falling back to client.Log, then zerolog.Nop.
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

func (s *BeeperStreamSender) requireClient() (*Client, error) {
	if s == nil {
		return requireStreamClient(nil, "sender")
	}
	return requireStreamClient(s.client, "sender")
}

func (s *BeeperStreamSender) queuePendingSubscribe(ctx context.Context, evt *event.Event) {
	if evt == nil {
		return
	}
	cloned := clonePendingSubscribeEvent(evt)
	if cloned == nil {
		return
	}
	now := s.now()
	s.pendingLock.Lock()
	defer s.pendingLock.Unlock()
	s.pendingSubscribe = append(s.pendingSubscribe, pendingSubscribeEvent{
		evt:        cloned,
		receivedAt: now,
	})
	if len(s.pendingSubscribe) > maxPendingSubscribes {
		s.pendingSubscribe = s.pendingSubscribe[len(s.pendingSubscribe)-maxPendingSubscribes:]
	}
	zerolog.Ctx(ctx).Debug().
		Int("pending_subscribes", len(s.pendingSubscribe)).
		Str("sender", evt.Sender.String()).
		Str("event_type", evt.Type.Type).
		Str("to_device_id", evt.ToDeviceID.String()).
		Msg("Queued subscribe for possible future beeper stream registration")
}

func (s *BeeperStreamSender) replayPendingSubscribes(ctx context.Context) {
	now := s.now()
	s.pendingLock.Lock()
	pending := append([]pendingSubscribeEvent(nil), s.pendingSubscribe...)
	s.pendingLock.Unlock()
	if len(pending) == 0 {
		return
	}
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

func clonePendingSubscribeEvent(evt *event.Event) *event.Event {
	if evt == nil {
		return nil
	}
	cloned := &event.Event{
		Sender:     evt.Sender,
		ToUserID:   evt.ToUserID,
		ToDeviceID: evt.ToDeviceID,
		Type:       evt.Type,
	}
	switch evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		subscribe, ok := evt.Content.Parsed.(*event.BeeperStreamSubscribeEventContent)
		if !ok {
			return nil
		}
		contentCopy := *subscribe
		cloned.Content = event.Content{Parsed: &contentCopy}
	case event.ToDeviceEncrypted:
		encrypted, ok := evt.Content.Parsed.(*event.EncryptedEventContent)
		if !ok {
			return nil
		}
		contentCopy := *encrypted
		cloned.Content = event.Content{Parsed: &contentCopy}
	default:
		return nil
	}
	return cloned
}

func (state *beeperStreamState) activeSubscribers(now time.Time) []beeperStreamSubscriber {
	active := make([]beeperStreamSubscriber, 0, len(state.subscribers))
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

func (state *beeperStreamState) getGCM() (cipher.AEAD, bool) {
	return state.gcm, state.gcm != nil
}

func BeeperStreamDescriptorEqual(a, b *event.BeeperStreamInfo) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	case a.UserID != b.UserID || a.DeviceID != b.DeviceID || a.Type != b.Type || a.ExpiryMS != b.ExpiryMS:
		return false
	case a.Encryption == nil || b.Encryption == nil:
		return a.Encryption == b.Encryption
	default:
		return a.Encryption.Algorithm == b.Encryption.Algorithm && a.Encryption.Key == b.Encryption.Key && a.Encryption.StreamID == b.Encryption.StreamID
	}
}

func ResolveBeeperStreamSubscribeExpiry(descriptor *event.BeeperStreamInfo, defaultExpiry time.Duration) time.Duration {
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

func cloneBeeperStreamInfo(info *event.BeeperStreamInfo) *event.BeeperStreamInfo {
	if info == nil {
		return nil
	}
	cloned := *info
	if info.Encryption != nil {
		enc := *info.Encryption
		cloned.Encryption = &enc
	}
	return &cloned
}

func validateBeeperStreamDescriptor(info *event.BeeperStreamInfo) error {
	if info == nil {
		return fmt.Errorf("missing beeper stream descriptor")
	} else if info.UserID == "" || info.DeviceID == "" || info.Type == "" {
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

// BeeperStreamDescriptor holds the stream info to embed in the initial Matrix event.
// Returned by PrepareStream; call Activate after sending the Matrix event to start publishing.
type BeeperStreamDescriptor struct {
	publisher *BeeperStreamPublisher
	roomID    id.RoomID
	// Info should be embedded in the com.beeper.stream field of the Matrix message event.
	Info *event.BeeperStreamInfo

	lock      sync.Mutex
	activated bool
}

// activateStream registers a new stream state. Called by Activate and BeeperStreamTransport.Start.
func (s *BeeperStreamSender) activateStream(ctx context.Context, roomID id.RoomID, eventID id.EventID, info *event.BeeperStreamInfo, authorizeSubscriber func(context.Context, *BeeperStreamSubscribeRequest) bool) error {
	descriptor := cloneBeeperStreamInfo(info)
	if err := validateBeeperStreamDescriptor(descriptor); err != nil {
		return err
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
		key:                 key,
		descriptor:          descriptor,
		authorizeSubscriber: authorizeSubscriber,
		subscribers:         make(map[beeperStreamSubscriber]time.Time),
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

// Activate starts the stream after the Matrix message event has been sent.
// eventID is the ID returned by the send call. Returns a handle for publishing updates.
func (d *BeeperStreamDescriptor) Activate(ctx context.Context, eventID id.EventID) (*BeeperStream, error) {
	d.lock.Lock()
	if d.publisher == nil || d.Info == nil {
		d.lock.Unlock()
		return nil, fmt.Errorf("missing beeper stream descriptor")
	} else if d.roomID == "" || eventID == "" {
		d.lock.Unlock()
		return nil, fmt.Errorf("missing beeper stream identifiers")
	} else if d.activated {
		d.lock.Unlock()
		return nil, fmt.Errorf("beeper stream descriptor already activated")
	}
	s, err := d.publisher.requireSender()
	if err != nil {
		d.lock.Unlock()
		return nil, err
	}
	if err = s.activateStream(ctx, d.roomID, eventID, d.Info, d.publisher.authorizeSubscriber); err != nil {
		d.lock.Unlock()
		return nil, err
	}
	descriptor := cloneBeeperStreamInfo(d.Info)
	d.activated = true
	d.lock.Unlock()
	return &BeeperStream{
		publisher:  d.publisher,
		roomID:     d.roomID,
		eventID:    eventID,
		descriptor: descriptor,
	}, nil
}

// BeeperStream is a handle for an active stream.
// Created by BeeperStreamDescriptor.Activate; call Publish and Finish on it.
type BeeperStream struct {
	publisher  *BeeperStreamPublisher
	roomID     id.RoomID
	eventID    id.EventID
	descriptor *event.BeeperStreamInfo
}

func (s *BeeperStream) RoomID() id.RoomID   { return s.roomID }
func (s *BeeperStream) EventID() id.EventID { return s.eventID }
func (s *BeeperStream) Descriptor() *event.BeeperStreamInfo {
	return cloneBeeperStreamInfo(s.descriptor)
}

// Publish sends an update to all active subscribers.
func (s *BeeperStream) Publish(ctx context.Context, content map[string]any) error {
	return s.publisher.publish(ctx, s.roomID, s.eventID, content)
}

// Finish marks the stream as done and cleans up after a grace period.
func (s *BeeperStream) Finish(ctx context.Context) error {
	return s.publisher.finish(ctx, s.roomID, s.eventID)
}

// PrepareStream builds a stream descriptor for the given room and stream type.
// Embed the returned BeeperStreamDescriptor.Info in the Matrix message event's com.beeper.stream field.
// After sending the event and getting its ID, call Activate to start publishing.
func (p *BeeperStreamPublisher) PrepareStream(ctx context.Context, roomID id.RoomID, streamType string) (*BeeperStreamDescriptor, error) {
	s, err := p.requireSender()
	if err != nil {
		return nil, err
	} else if roomID == "" || streamType == "" {
		return nil, fmt.Errorf("missing beeper stream descriptor request fields")
	}
	client, err := s.requireClient()
	if err != nil {
		return nil, err
	}
	info := &event.BeeperStreamInfo{
		UserID:   client.UserID,
		DeviceID: client.DeviceID,
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
	return &BeeperStreamDescriptor{
		publisher: p,
		roomID:    roomID,
		Info:      info,
	}, nil
}

// NewBeeperStreamPublisher creates a stream publisher for this client.
// This is the entry point for non-bridge bots: the underlying sender singleton is created
// on first call and its to-device interceptor is registered automatically.
func (cli *Client) NewBeeperStreamPublisher(publisherOpts *BeeperStreamPublisherOptions, senderOpts *BeeperStreamSenderOptions) *BeeperStreamPublisher {
	return cli.GetOrCreateBeeperStreamSender(senderOpts).NewPublisher(publisherOpts)
}

type beeperStreamPublisherTransport struct {
	publisher *BeeperStreamPublisher
}

// NewTransport returns a BeeperStreamTransport backed by this publisher.
// Multiple transports can share the same publisher safely; all state is in the underlying sender.
func (p *BeeperStreamPublisher) NewTransport() BeeperStreamTransport {
	return &beeperStreamPublisherTransport{publisher: p}
}

func (t *beeperStreamPublisherTransport) BuildDescriptor(ctx context.Context, roomID id.RoomID, streamType string) (*event.BeeperStreamInfo, error) {
	desc, err := t.publisher.PrepareStream(ctx, roomID, streamType)
	if err != nil {
		return nil, err
	}
	return desc.Info, nil
}

func (t *beeperStreamPublisherTransport) Start(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error {
	s, err := t.publisher.requireSender()
	if err != nil {
		return err
	}
	return s.activateStream(ctx, roomID, eventID, descriptor, t.publisher.authorizeSubscriber)
}

func (t *beeperStreamPublisherTransport) Publish(ctx context.Context, roomID id.RoomID, eventID id.EventID, content map[string]any) error {
	return t.publisher.publish(ctx, roomID, eventID, content)
}

func (t *beeperStreamPublisherTransport) Finish(ctx context.Context, roomID id.RoomID, eventID id.EventID) error {
	return t.publisher.finish(ctx, roomID, eventID)
}

func EncryptBeeperStreamEvent(logicalType event.Type, content *event.Content, streamID string, base64Key string) (*event.EncryptedEventContent, error) {
	gcm, err := newStreamGCM(base64Key)
	if err != nil {
		return nil, err
	}
	return encryptStreamPayload(logicalType, content, streamID, gcm)
}

func DecryptBeeperStreamEvent(content *event.EncryptedEventContent, base64Key string) (event.Type, *event.Content, error) {
	gcm, err := newStreamGCM(base64Key)
	if err != nil {
		return event.Type{}, nil, err
	}
	payload, err := decryptStreamPayload(content, gcm)
	if err != nil {
		return event.Type{}, nil, err
	}
	logicalType := event.Type{Type: payload.Type, Class: event.ToDeviceEventType}
	switch payload.Type {
	case event.ToDeviceBeeperStreamSubscribe.Type:
		logicalType = event.ToDeviceBeeperStreamSubscribe
	case event.ToDeviceBeeperStreamUpdate.Type:
		logicalType = event.ToDeviceBeeperStreamUpdate
	}
	var parsed event.Content
	if err = json.Unmarshal(payload.Content, &parsed); err != nil {
		return event.Type{}, nil, err
	}
	if err = parsed.ParseRaw(logicalType); err != nil {
		return event.Type{}, nil, err
	}
	return logicalType, &parsed, nil
}

func makeToDeviceContent(descriptor *event.BeeperStreamInfo, gcm cipher.AEAD, logicalType event.Type, payload *event.Content) (event.Type, *event.Content, error) {
	if descriptor != nil && descriptor.Encryption != nil && gcm != nil {
		encrypted, err := encryptStreamPayload(logicalType, payload, descriptor.Encryption.StreamID, gcm)
		if err != nil {
			return event.Type{}, nil, err
		}
		return event.ToDeviceEncrypted, &event.Content{Parsed: encrypted}, nil
	}
	return logicalType, payload, nil
}

func makeStreamKey() string {
	return base64.RawStdEncoding.EncodeToString(random.Bytes(32))
}

func makeStreamID() string {
	return base64.RawStdEncoding.EncodeToString(random.Bytes(16))
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

func encryptStreamPayload(logicalType event.Type, payload *event.Content, streamID string, gcm cipher.AEAD) (*event.EncryptedEventContent, error) {
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
	iv := make([]byte, gcm.NonceSize())
	if _, err = cryptorand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate beeper stream IV: %w", err)
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	return &event.EncryptedEventContent{
		Algorithm:        id.AlgorithmBeeperStreamAESGCM,
		IV:               base64.RawStdEncoding.EncodeToString(iv),
		StreamID:         streamID,
		StreamCiphertext: []byte(base64.RawStdEncoding.EncodeToString(ciphertext)),
	}, nil
}

func decryptStreamPayload(content *event.EncryptedEventContent, gcm cipher.AEAD) (*beeperStreamEncryptedPayload, error) {
	iv, err := base64.RawStdEncoding.DecodeString(content.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode beeper stream IV: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(string(content.StreamCiphertext))
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
	raw := maps.Clone(content)
	if _, ok := raw["room_id"]; ok {
		return nil, fmt.Errorf("beeper stream payload may not override room_id")
	} else if _, ok = raw["event_id"]; ok {
		return nil, fmt.Errorf("beeper stream payload may not override event_id")
	}
	return &event.Content{
		Parsed: &event.BeeperStreamUpdateEventContent{
			RoomID:  roomID,
			EventID: eventID,
		},
		Raw: raw,
	}, nil
}
