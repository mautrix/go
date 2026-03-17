// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package streamhelper

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

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	DefaultStreamExpiry  = 30 * time.Minute
	streamCleanupGrace   = 30 * time.Second
	pendingSubscribeTTL  = 5 * time.Second
	maxPendingSubscribes = 64
)

type HelperOptions struct {
	Logger      *zerolog.Logger
	IsEncrypted func(context.Context, id.RoomID) (bool, error)
}

type GeneratorOptions struct {
	AuthorizeSubscriber func(context.Context, id.UserID) bool
}

type StreamDescriptorRequest struct {
	RoomID id.RoomID
	Type   string
}

type StartRequest struct {
	RoomID     id.RoomID
	EventID    id.EventID
	Type       string
	Descriptor *event.BeeperStreamInfo
}

type PublishRequest struct {
	RoomID  id.RoomID
	EventID id.EventID
	Content map[string]any
}

type FinishRequest struct {
	RoomID  id.RoomID
	EventID id.EventID
}

type Helper struct {
	client *mautrix.Client
	log    zerolog.Logger

	isEncrypted func(context.Context, id.RoomID) (bool, error)
	now         func() time.Time

	lock    sync.Mutex
	streams map[streamKey]*streamState

	pendingLock               sync.Mutex
	pendingEncryptedSubscribe []pendingEncryptedSubscribe
}

type Generator struct {
	helper              *Helper
	authorizeSubscriber func(context.Context, id.UserID) bool
}

type streamKey struct {
	roomID  id.RoomID
	eventID id.EventID
}

type streamSubscriber struct {
	userID   id.UserID
	deviceID id.DeviceID
}

type streamState struct {
	key        streamKey
	descriptor *event.BeeperStreamInfo
	updates    []*event.Content

	authorizeSubscriber func(context.Context, id.UserID) bool

	subscribers map[streamSubscriber]time.Time
	finished    bool
	cleanup     *time.Timer

	cachedGCM cipher.AEAD
}

type streamEncryptedPayload struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

type pendingEncryptedSubscribe struct {
	evt        *event.Event
	receivedAt time.Time
}

func New(client *mautrix.Client, opts *HelperOptions) *Helper {
	var log zerolog.Logger
	switch {
	case opts != nil && opts.Logger != nil:
		log = opts.Logger.With().Str("component", "streamhelper").Logger()
	case client != nil:
		log = client.Log.With().Str("component", "streamhelper").Logger()
	default:
		log = zerolog.Nop()
	}
	helper := &Helper{
		client:  client,
		log:     log,
		now:     time.Now,
		streams: make(map[streamKey]*streamState),
	}
	if opts != nil && opts.IsEncrypted != nil {
		helper.isEncrypted = opts.IsEncrypted
	} else {
		helper.isEncrypted = helper.defaultIsEncrypted
	}
	return helper
}

func (h *Helper) defaultIsEncrypted(ctx context.Context, roomID id.RoomID) (bool, error) {
	if h.client == nil || h.client.StateStore == nil {
		return false, nil
	}
	return h.client.StateStore.IsEncrypted(ctx, roomID)
}

func (h *Helper) NewGenerator(opts *GeneratorOptions) *Generator {
	gen := &Generator{helper: h}
	if opts != nil {
		gen.authorizeSubscriber = opts.AuthorizeSubscriber
	}
	return gen
}

func (g *Generator) BuildDescriptor(ctx context.Context, req *StreamDescriptorRequest) (*event.BeeperStreamInfo, error) {
	if g == nil || g.helper == nil {
		return nil, fmt.Errorf("stream helper is nil")
	} else if req == nil || req.RoomID == "" || req.Type == "" {
		return nil, fmt.Errorf("missing stream descriptor request fields")
	}
	client, err := g.helper.requireClient()
	if err != nil {
		return nil, err
	}
	desc := &event.BeeperStreamInfo{
		UserID:   client.UserID,
		DeviceID: client.DeviceID,
		Type:     req.Type,
		ExpiryMS: DefaultStreamExpiry.Milliseconds(),
	}
	isEncrypted, err := g.helper.isEncrypted(ctx, req.RoomID)
	if err != nil {
		return nil, err
	}
	if isEncrypted {
		desc.Encryption = &event.BeeperStreamEncryptionInfo{
			Algorithm: id.AlgorithmBeeperStreamAESGCM,
			Key:       makeStreamKey(),
		}
	}
	return desc, nil
}

func (g *Generator) Start(ctx context.Context, req *StartRequest) error {
	if g == nil || g.helper == nil {
		return fmt.Errorf("stream helper is nil")
	} else if req == nil || req.Descriptor == nil {
		return fmt.Errorf("missing stream descriptor")
	} else if req.RoomID == "" || req.EventID == "" || req.Type == "" {
		return fmt.Errorf("missing stream identifiers")
	}

	key := streamKey{roomID: req.RoomID, eventID: req.EventID}
	h := g.helper
	h.lock.Lock()
	if _, exists := h.streams[key]; exists {
		h.lock.Unlock()
		return fmt.Errorf("stream %s/%s already started", req.RoomID, req.EventID)
	}
	state := &streamState{
		key:                 key,
		descriptor:          req.Descriptor,
		authorizeSubscriber: g.authorizeSubscriber,
		subscribers:         make(map[streamSubscriber]time.Time),
	}
	if req.Descriptor.Encryption != nil {
		gcm, err := newStreamGCM(req.Descriptor.Encryption.Key)
		if err != nil {
			h.lock.Unlock()
			return fmt.Errorf("failed to initialize stream cipher: %w", err)
		}
		state.cachedGCM = gcm
	}
	h.streams[key] = state
	h.lock.Unlock()
	h.replayPendingEncryptedSubscribes(ctx)
	return nil
}

func (g *Generator) Publish(ctx context.Context, req *PublishRequest) error {
	if g == nil || g.helper == nil {
		return fmt.Errorf("stream helper is nil")
	} else if req == nil || req.RoomID == "" || req.EventID == "" {
		return fmt.Errorf("missing stream identifiers")
	}
	desc, gcm, update, subscribers, err := g.helper.recordUpdate(req)
	if err != nil {
		return err
	}
	return g.helper.sendUpdateToSubscribers(ctx, desc, gcm, update, subscribers)
}

func (g *Generator) Finish(_ context.Context, req *FinishRequest) error {
	if g == nil || g.helper == nil {
		return fmt.Errorf("stream helper is nil")
	} else if req == nil || req.RoomID == "" || req.EventID == "" {
		return fmt.Errorf("missing stream identifiers")
	}
	key := streamKey{roomID: req.RoomID, eventID: req.EventID}
	h := g.helper
	h.lock.Lock()
	defer h.lock.Unlock()
	state := h.streams[key]
	if state == nil {
		return fmt.Errorf("stream %s/%s not found", req.RoomID, req.EventID)
	}
	state.finished = true
	state.subscribers = nil
	if state.cleanup != nil {
		state.cleanup.Stop()
	}
	state.cleanup = time.AfterFunc(streamCleanupGrace, func() {
		h.lock.Lock()
		defer h.lock.Unlock()
		delete(h.streams, key)
	})
	return nil
}

func (h *Helper) HandleToDeviceEvent(ctx context.Context, evt *event.Event) bool {
	if h == nil || evt == nil {
		return false
	}
	if evt.Content.Parsed == nil {
		_ = evt.Content.ParseRaw(evt.Type)
	}
	switch evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		return h.handleSubscribeEvent(ctx, evt)
	case event.ToDeviceEncrypted:
		return h.handleEncryptedEvent(ctx, evt)
	default:
		return false
	}
}

func (h *Helper) handleSubscribeEvent(ctx context.Context, evt *event.Event) bool {
	if h.isForDifferentDevice(evt) {
		return true
	}
	subscribe := event.CastOrDefault[event.BeeperStreamSubscribeEventContent](&evt.Content)
	if subscribe.RoomID == "" || subscribe.EventID == "" {
		return true
	}
	h.handleSubscribe(ctx, evt.Sender, subscribe)
	return true
}

func (h *Helper) handleEncryptedEvent(ctx context.Context, evt *event.Event) bool {
	content := evt.Content.AsEncrypted()
	if content.Algorithm != id.AlgorithmBeeperStreamAESGCM {
		return false
	} else if h.isForDifferentDevice(evt) {
		return true
	}
	log := zerolog.Ctx(ctx).With().
		Str("sender", evt.Sender.String()).
		Str("to_device_id", evt.ToDeviceID.String()).
		Str("room_id", content.RoomID.String()).
		Str("event_id", content.EventID.String()).
		Logger()
	states := h.collectEncryptedCandidates(content)

	for _, state := range states {
		if h.tryDecryptAndSubscribe(ctx, evt, content, state) {
			return true
		}
	}
	log.Debug().Msg("Custom encrypted to-device event doesn't match an active stream, queueing as pending")
	h.queuePendingEncryptedSubscribe(ctx, evt)
	return true
}

func (h *Helper) collectEncryptedCandidates(content *event.EncryptedEventContent) []*streamState {
	h.lock.Lock()
	defer h.lock.Unlock()
	states := make([]*streamState, 0, len(h.streams))
	if content.RoomID != "" && content.EventID != "" {
		key := streamKey{roomID: content.RoomID, eventID: content.EventID}
		if state := h.streams[key]; state != nil && state.descriptor != nil && state.descriptor.Encryption != nil {
			states = append(states, state)
		}
	} else {
		for _, state := range h.streams {
			if state.descriptor == nil || state.descriptor.Encryption == nil {
				continue
			}
			states = append(states, state)
		}
	}
	return states
}

func (h *Helper) isForDifferentDevice(evt *event.Event) bool {
	if evt == nil || h.client == nil {
		return h.client == nil
	}
	if evt.ToUserID != "" && evt.ToUserID != h.client.UserID {
		return true
	}
	return evt.ToDeviceID != "" && h.client.DeviceID != "" && evt.ToDeviceID != h.client.DeviceID
}

func (h *Helper) tryDecryptAndSubscribe(ctx context.Context, evt *event.Event, content *event.EncryptedEventContent, state *streamState) bool {
	log := zerolog.Ctx(ctx).With().
		Str("sender", evt.Sender.String()).
		Str("stream_room_id", state.key.roomID.String()).
		Str("stream_event_id", state.key.eventID.String()).
		Logger()
	gcm, err := state.getGCM()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get stream GCM cipher")
		return false
	}
	payload, err := decryptStreamPayload(content, gcm)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to decrypt custom encrypted subscribe")
		return false
	}
	if payload.Type != event.ToDeviceBeeperStreamSubscribe.Type {
		log.Debug().Str("payload_type", payload.Type).Msg("Ignoring decrypted custom stream payload with unexpected type")
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
			Msg("Decrypted custom subscribe payload did not match stream candidate")
		return false
	}
	log.Debug().
		Str("subscribe_device_id", subscribe.DeviceID.String()).
		Int64("subscribe_expiry_ms", subscribe.ExpiryMS).
		Msg("Matched custom encrypted subscribe payload to active stream")
	h.handleSubscribe(ctx, evt.Sender, &subscribe)
	return true
}

func (h *Helper) handleSubscribe(ctx context.Context, sender id.UserID, subscribe *event.BeeperStreamSubscribeEventContent) {
	if subscribe == nil {
		return
	}
	key := streamKey{roomID: subscribe.RoomID, eventID: subscribe.EventID}
	h.lock.Lock()
	state := h.streams[key]
	if state == nil || state.finished {
		h.lock.Unlock()
		zerolog.Ctx(ctx).Debug().
			Str("sender", sender.String()).
			Str("room_id", subscribe.RoomID.String()).
			Str("event_id", subscribe.EventID.String()).
			Bool("stream_found", state != nil).
			Bool("stream_finished", state != nil && state.finished).
			Msg("Ignoring subscribe for missing or finished stream")
		return
	}
	authFunc := state.authorizeSubscriber
	h.lock.Unlock()

	// Authorize outside the lock to avoid blocking all stream operations on a DB query.
	if authFunc != nil && !authFunc(ctx, sender) {
		zerolog.Ctx(ctx).Debug().Stringer("sender", sender).Msg("Ignoring stream subscribe from unauthorized user")
		return
	}

	h.lock.Lock()
	// Re-check state after re-acquiring lock (may have finished during authorization).
	state = h.streams[key]
	if state == nil || state.finished {
		h.lock.Unlock()
		return
	}
	expiry := time.Duration(subscribe.ExpiryMS) * time.Millisecond
	if expiry <= 0 {
		expiry = time.Duration(state.descriptor.ExpiryMS) * time.Millisecond
	}
	if expiry <= 0 {
		expiry = DefaultStreamExpiry
	}
	sub := streamSubscriber{userID: sender, deviceID: subscribe.DeviceID}
	// Register subscriber before replaying so that updates published during replay
	// are also delivered. Clients should handle potential duplicate updates.
	state.subscribers[sub] = h.now().Add(expiry)
	desc := state.descriptor
	gcm, _ := state.getGCM()
	updates := append([]*event.Content(nil), state.updates...)
	h.lock.Unlock()

	zerolog.Ctx(ctx).Debug().
		Str("sender", sender.String()).
		Str("room_id", subscribe.RoomID.String()).
		Str("event_id", subscribe.EventID.String()).
		Str("device_id", subscribe.DeviceID.String()).
		Int("replay_count", len(updates)).
		Msg("Replaying stream updates to new subscriber")

	for _, update := range updates {
		if err := h.sendUpdateToSubscribers(ctx, desc, gcm, update, []streamSubscriber{sub}); err != nil {
			zerolog.Ctx(ctx).Err(err).
				Str("room_id", subscribe.RoomID.String()).
				Str("event_id", subscribe.EventID.String()).
				Str("subscriber", sender.String()).
				Msg("Failed to replay stream updates to new subscriber, removing subscriber")
			// Remove subscriber on replay failure to avoid gaps in the stream.
			h.lock.Lock()
			state = h.streams[key]
			if state != nil {
				delete(state.subscribers, sub)
			}
			h.lock.Unlock()
			return
		}
	}
}

func (h *Helper) recordUpdate(req *PublishRequest) (desc *event.BeeperStreamInfo, gcm cipher.AEAD, update *event.Content, subscribers []streamSubscriber, err error) {
	update, err = newStreamUpdateContent(req)
	if err != nil {
		return
	}
	key := streamKey{roomID: req.RoomID, eventID: req.EventID}
	h.lock.Lock()
	defer h.lock.Unlock()
	state := h.streams[key]
	if state == nil {
		err = fmt.Errorf("stream %s/%s not found", req.RoomID, req.EventID)
		return
	} else if state.finished {
		err = fmt.Errorf("stream %s/%s already finished", req.RoomID, req.EventID)
		return
	}
	state.updates = append(state.updates, update)
	desc = state.descriptor
	gcm, _ = state.getGCM()
	subscribers = state.activeSubscribers(h.now())
	return
}

func (h *Helper) sendUpdateToSubscribers(ctx context.Context, descriptor *event.BeeperStreamInfo, gcm cipher.AEAD, update *event.Content, subscribers []streamSubscriber) error {
	if len(subscribers) == 0 {
		return nil
	}
	client, err := h.requireClient()
	if err != nil {
		return err
	}
	eventType, content, err := makeToDeviceContent(descriptor, gcm, event.ToDeviceBeeperStreamUpdate, update)
	if err != nil {
		return err
	}
	req := &mautrix.ReqSendToDevice{
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

func (h *Helper) requireClient() (*mautrix.Client, error) {
	if h == nil || h.client == nil {
		return nil, fmt.Errorf("stream helper doesn't have a client")
	} else if h.client.UserID == "" {
		return nil, fmt.Errorf("stream helper client isn't logged in")
	} else if h.client.DeviceID == "" {
		return nil, fmt.Errorf("stream helper client doesn't have a device ID")
	}
	return h.client, nil
}

func (h *Helper) queuePendingEncryptedSubscribe(ctx context.Context, evt *event.Event) {
	if evt == nil {
		return
	}
	cloned := &event.Event{
		Sender:     evt.Sender,
		ToUserID:   evt.ToUserID,
		ToDeviceID: evt.ToDeviceID,
		Type:       evt.Type,
	}
	if encrypted := evt.Content.AsEncrypted(); encrypted != nil {
		contentCopy := *encrypted
		cloned.Content = event.Content{Parsed: &contentCopy}
	}
	now := h.now()
	h.pendingLock.Lock()
	defer h.pendingLock.Unlock()
	var filtered []pendingEncryptedSubscribe
	for _, pending := range h.pendingEncryptedSubscribe {
		if now.Sub(pending.receivedAt) <= pendingSubscribeTTL {
			filtered = append(filtered, pending)
		}
	}
	h.pendingEncryptedSubscribe = append(filtered, pendingEncryptedSubscribe{
		evt:        cloned,
		receivedAt: now,
	})
	if len(h.pendingEncryptedSubscribe) > maxPendingSubscribes {
		h.pendingEncryptedSubscribe = h.pendingEncryptedSubscribe[len(h.pendingEncryptedSubscribe)-maxPendingSubscribes:]
	}
	zerolog.Ctx(ctx).Debug().
		Int("pending_subscribes", len(h.pendingEncryptedSubscribe)).
		Str("sender", evt.Sender.String()).
		Str("to_device_id", evt.ToDeviceID.String()).
		Msg("Queued custom encrypted subscribe for possible future stream registration")
}

func (h *Helper) replayPendingEncryptedSubscribes(ctx context.Context) {
	now := h.now()
	h.pendingLock.Lock()
	pending := append([]pendingEncryptedSubscribe(nil), h.pendingEncryptedSubscribe...)
	h.pendingLock.Unlock()
	if len(pending) == 0 {
		return
	}
	consumed := make(map[*event.Event]struct{})
	for _, candidate := range pending {
		if candidate.evt == nil || now.Sub(candidate.receivedAt) > pendingSubscribeTTL {
			continue
		}
		content := candidate.evt.Content.AsEncrypted()
		if content == nil {
			continue
		}
		if h.tryPendingEncryptedSubscribe(ctx, candidate.evt, content) {
			consumed[candidate.evt] = struct{}{}
		}
	}
	if len(consumed) == 0 {
		return
	}
	h.pendingLock.Lock()
	defer h.pendingLock.Unlock()
	var filtered []pendingEncryptedSubscribe
	for _, candidate := range h.pendingEncryptedSubscribe {
		if candidate.evt == nil || now.Sub(candidate.receivedAt) > pendingSubscribeTTL {
			continue
		}
		if _, ok := consumed[candidate.evt]; ok {
			continue
		}
		filtered = append(filtered, candidate)
	}
	h.pendingEncryptedSubscribe = filtered
	zerolog.Ctx(ctx).Debug().
		Int("replayed_subscribes", len(consumed)).
		Int("pending_subscribes", len(h.pendingEncryptedSubscribe)).
		Msg("Replayed pending custom encrypted subscribes after stream registration")
}

func (h *Helper) tryPendingEncryptedSubscribe(ctx context.Context, evt *event.Event, content *event.EncryptedEventContent) bool {
	states := h.collectEncryptedCandidates(content)
	for _, state := range states {
		if h.tryDecryptAndSubscribe(ctx, evt, content, state) {
			return true
		}
	}
	return false
}

func (state *streamState) activeSubscribers(now time.Time) []streamSubscriber {
	active := make([]streamSubscriber, 0, len(state.subscribers))
	for subscriber, expiry := range state.subscribers {
		if now.After(expiry) {
			delete(state.subscribers, subscriber)
			continue
		}
		active = append(active, subscriber)
	}
	return active
}

func makeToDeviceContent(descriptor *event.BeeperStreamInfo, gcm cipher.AEAD, logicalType event.Type, payload *event.Content) (event.Type, *event.Content, error) {
	if descriptor != nil && descriptor.Encryption != nil && gcm != nil {
		roomID, eventID := streamRouteFromContent(payload)
		encrypted, err := encryptStreamPayload(logicalType, payload, roomID, eventID, gcm)
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

func (s *streamState) getGCM() (cipher.AEAD, error) {
	if s.cachedGCM != nil {
		return s.cachedGCM, nil
	}
	if s.descriptor == nil || s.descriptor.Encryption == nil {
		return nil, fmt.Errorf("stream has no encryption info")
	}
	gcm, err := newStreamGCM(s.descriptor.Encryption.Key)
	if err != nil {
		return nil, err
	}
	s.cachedGCM = gcm
	return gcm, nil
}

func encryptStreamPayload(logicalType event.Type, payload *event.Content, roomID id.RoomID, eventID id.EventID, gcm cipher.AEAD) (*event.EncryptedEventContent, error) {
	plaintextContent, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(streamEncryptedPayload{
		Type:    logicalType.Type,
		Content: plaintextContent,
	})
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err = cryptorand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate stream IV: %w", err)
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	return &event.EncryptedEventContent{
		Algorithm:        id.AlgorithmBeeperStreamAESGCM,
		IV:               base64.RawStdEncoding.EncodeToString(iv),
		RoomID:           roomID,
		EventID:          eventID,
		StreamCiphertext: []byte(base64.RawStdEncoding.EncodeToString(ciphertext)),
	}, nil
}

func decryptStreamPayload(content *event.EncryptedEventContent, gcm cipher.AEAD) (*streamEncryptedPayload, error) {
	iv, err := base64.RawStdEncoding.DecodeString(content.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode stream IV: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(string(content.StreamCiphertext))
	if err != nil {
		return nil, fmt.Errorf("failed to decode stream ciphertext: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	var payload streamEncryptedPayload
	if err = json.Unmarshal(plaintext, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func newStreamUpdateContent(req *PublishRequest) (*event.Content, error) {
	if req == nil || req.RoomID == "" || req.EventID == "" {
		return nil, fmt.Errorf("missing stream identifiers")
	}
	raw := maps.Clone(req.Content)
	if _, ok := raw["room_id"]; ok {
		return nil, fmt.Errorf("stream payload may not override room_id")
	} else if _, ok = raw["event_id"]; ok {
		return nil, fmt.Errorf("stream payload may not override event_id")
	}
	return &event.Content{
		Parsed: &event.BeeperStreamUpdateEventContent{
			RoomID:  req.RoomID,
			EventID: req.EventID,
		},
		Raw: raw,
	}, nil
}

func streamRouteFromContent(content *event.Content) (id.RoomID, id.EventID) {
	if content == nil {
		return "", ""
	}
	if update := event.CastOrDefault[event.BeeperStreamUpdateEventContent](content); update != nil && (update.RoomID != "" || update.EventID != "") {
		return update.RoomID, update.EventID
	}
	return "", ""
}
