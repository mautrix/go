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
	beeperStreamReceiverComponentName   = "beeper_stream_receiver"
)

type BeeperStreamSenderOptions struct {
	Logger              *zerolog.Logger
	IsEncrypted         func(context.Context, id.RoomID) (bool, error)
	AuthorizeSubscriber func(context.Context, *BeeperStreamSubscribeRequest) bool
}

type BeeperStreamSubscribeRequest struct {
	RoomID   id.RoomID
	EventID  id.EventID
	UserID   id.UserID
	DeviceID id.DeviceID
	Expiry   time.Duration
}

type BeeperStreamSender struct {
	client *Client
	log    zerolog.Logger

	authorizeSubscriber func(context.Context, *BeeperStreamSubscribeRequest) bool
	isEncrypted         func(context.Context, id.RoomID) (bool, error)
	now                 func() time.Time

	lock              sync.RWMutex
	streams           map[beeperStreamKey]*beeperStreamState
	streamsByStreamID map[string]*beeperStreamState

	pendingLock      sync.Mutex
	pendingSubscribe []pendingSubscribeEvent
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
	if opts != nil {
		sender.authorizeSubscriber = opts.AuthorizeSubscriber
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
	s.lock.RLock()
	state := s.streamsByStreamID[content.StreamID]
	s.lock.RUnlock()
	if state == nil {
		return false
	}
	return s.tryDecryptAndSubscribe(ctx, evt, content, state)
}

func (s *BeeperStreamSender) isForDifferentDevice(evt *event.Event) bool {
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
	expiry := ResolveBeeperStreamSubscribeExpiry(state.descriptor, authReq.Expiry)
	sub := beeperStreamSubscriber{userID: sender, deviceID: subscribe.DeviceID}
	state.subscribers[sub] = s.now().Add(expiry)
	desc := state.descriptor
	gcm := state.gcm
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
	pending := append([]pendingSubscribeEvent(nil), s.pendingSubscribe...)
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

func BeeperStreamDescriptorEqual(a, b *event.BeeperStreamInfo) bool {
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

// BeeperStreamDescriptor holds the `com.beeper.stream` payload for a Matrix event.
type BeeperStreamDescriptor struct {
	sender *BeeperStreamSender
	roomID id.RoomID
	// Info is the `com.beeper.stream` payload.
	Info *event.BeeperStreamInfo
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

// Activate registers the sent Matrix event and returns a stream handle.
func (d *BeeperStreamDescriptor) Activate(ctx context.Context, eventID id.EventID) (*BeeperStream, error) {
	if d.sender == nil || d.Info == nil {
		return nil, fmt.Errorf("missing beeper stream descriptor")
	} else if d.roomID == "" || eventID == "" {
		return nil, fmt.Errorf("missing beeper stream identifiers")
	}
	if err := d.sender.activateStream(ctx, d.roomID, eventID, d.Info); err != nil {
		return nil, err
	}
	return &BeeperStream{
		sender:  d.sender,
		roomID:  d.roomID,
		eventID: eventID,
	}, nil
}

// BeeperStream publishes updates for an active stream.
type BeeperStream struct {
	sender  *BeeperStreamSender
	roomID  id.RoomID
	eventID id.EventID
}

// Publish sends an update to all active subscribers.
func (s *BeeperStream) Publish(ctx context.Context, content map[string]any) error {
	desc, gcm, update, subscribers, err := s.sender.recordUpdate(s.roomID, s.eventID, content)
	if err != nil {
		return err
	}
	return s.sender.sendUpdateToSubscribers(ctx, desc, gcm, update, subscribers)
}

// Finish closes the stream.
func (s *BeeperStream) Finish(_ context.Context) error {
	key := beeperStreamKey{roomID: s.roomID, eventID: s.eventID}
	s.sender.lock.Lock()
	defer s.sender.lock.Unlock()
	state := s.sender.streams[key]
	if state == nil {
		return fmt.Errorf("beeper stream %s/%s not found", s.roomID, s.eventID)
	}
	state.finished = true
	state.subscribers = nil
	if state.descriptor.Encryption != nil && state.descriptor.Encryption.StreamID != "" {
		delete(s.sender.streamsByStreamID, state.descriptor.Encryption.StreamID)
	}
	if state.cleanup != nil {
		state.cleanup.Stop()
	}
	state.cleanup = time.AfterFunc(streamCleanupGrace, func() {
		s.sender.lock.Lock()
		defer s.sender.lock.Unlock()
		delete(s.sender.streams, key)
	})
	return nil
}

// PrepareStream creates a stream descriptor for a Matrix event.
func (s *BeeperStreamSender) PrepareStream(ctx context.Context, roomID id.RoomID, streamType string) (*BeeperStreamDescriptor, error) {
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
	return &BeeperStreamDescriptor{
		sender: s,
		roomID: roomID,
		Info:   info,
	}, nil
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
