// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	DefaultStreamExpiry = 30 * time.Minute
	streamCleanupGrace  = 30 * time.Second
)

type BeeperStream interface {
	BuildDescriptor(ctx context.Context, req *StreamDescriptorRequest) (*event.BeeperStreamInfo, error)
	Start(ctx context.Context, req *StartStreamRequest) error
	Publish(ctx context.Context, req *PublishStreamRequest) error
	Finish(ctx context.Context, req *FinishStreamRequest) error
}

type StreamTransport = BeeperStream

type StreamDescriptorRequest struct {
	RoomID id.RoomID
	Type   string
}

type StartStreamRequest struct {
	RoomID     id.RoomID
	EventID    id.EventID
	Type       string
	Descriptor *event.BeeperStreamInfo
}

type PublishStreamRequest struct {
	RoomID  id.RoomID
	EventID id.EventID
	Content map[string]any
}

type FinishStreamRequest struct {
	RoomID  id.RoomID
	EventID id.EventID
}

type beeperStreamHandler struct {
	br *Bridge
}

type userLoginBeeperStream struct {
	login   *UserLogin
	handler *beeperStreamHandler

	lock    sync.Mutex
	streams map[streamKey]*streamState
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

	subscribers map[streamSubscriber]time.Time
	finished    bool
	cleanup     *time.Timer
}

type streamEncryptedPayload struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

func newBeeperStreamHandler(br *Bridge) *beeperStreamHandler {
	return &beeperStreamHandler{br: br}
}

func newUserLoginBeeperStream(login *UserLogin, handler *beeperStreamHandler) BeeperStream {
	return &userLoginBeeperStream{
		login:   login,
		handler: handler,
		streams: make(map[streamKey]*streamState),
	}
}

func (st *userLoginBeeperStream) BuildDescriptor(ctx context.Context, req *StreamDescriptorRequest) (*event.BeeperStreamInfo, error) {
	sender, err := st.handler.getSender()
	if err != nil {
		return nil, err
	}
	desc := &event.BeeperStreamInfo{
		UserID:   st.login.Bridge.Bot.GetMXID(),
		DeviceID: sender.GetDeviceID(),
		Type:     req.Type,
		ExpiryMS: DefaultStreamExpiry.Milliseconds(),
	}
	isEncrypted, err := st.handler.isEncryptedRoom(ctx, req.RoomID)
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

func (st *userLoginBeeperStream) Start(_ context.Context, req *StartStreamRequest) error {
	if req == nil || req.Descriptor == nil {
		return fmt.Errorf("missing stream descriptor")
	} else if req.RoomID == "" || req.EventID == "" || req.Type == "" {
		return fmt.Errorf("missing stream identifiers")
	}

	key := streamKey{roomID: req.RoomID, eventID: req.EventID}
	st.lock.Lock()
	defer st.lock.Unlock()
	if _, exists := st.streams[key]; exists {
		return fmt.Errorf("stream %s/%s already started", req.RoomID, req.EventID)
	}
	st.streams[key] = &streamState{
		key:         key,
		descriptor:  req.Descriptor,
		subscribers: make(map[streamSubscriber]time.Time),
	}
	return nil
}

func (st *userLoginBeeperStream) Publish(ctx context.Context, req *PublishStreamRequest) error {
	if req == nil || req.RoomID == "" || req.EventID == "" {
		return fmt.Errorf("missing stream identifiers")
	}
	desc, update, subscribers, err := st.recordUpdate(req)
	if err != nil {
		return err
	}
	return st.sendUpdateToSubscribers(ctx, desc, update, subscribers)
}

func (st *userLoginBeeperStream) recordUpdate(req *PublishStreamRequest) (desc *event.BeeperStreamInfo, update *event.Content, subscribers []streamSubscriber, err error) {
	key := streamKey{roomID: req.RoomID, eventID: req.EventID}
	st.lock.Lock()
	defer st.lock.Unlock()
	state := st.streams[key]
	if state == nil {
		err = fmt.Errorf("stream %s/%s not found", req.RoomID, req.EventID)
		return
	} else if state.finished {
		err = fmt.Errorf("stream %s/%s already finished", req.RoomID, req.EventID)
		return
	}
	update, err = newStreamUpdateContent(req)
	if err != nil {
		return
	}
	state.updates = append(state.updates, update)
	desc = state.descriptor
	subscribers = state.activeSubscribers(time.Now())
	return
}

func (st *userLoginBeeperStream) Finish(_ context.Context, req *FinishStreamRequest) error {
	if req == nil || req.RoomID == "" || req.EventID == "" {
		return fmt.Errorf("missing stream identifiers")
	}
	key := streamKey{roomID: req.RoomID, eventID: req.EventID}
	st.lock.Lock()
	defer st.lock.Unlock()
	state := st.streams[key]
	if state == nil {
		return fmt.Errorf("stream %s/%s not found", req.RoomID, req.EventID)
	}
	state.finished = true
	state.subscribers = nil
	if state.cleanup != nil {
		state.cleanup.Stop()
	}
	state.cleanup = time.AfterFunc(streamCleanupGrace, func() {
		st.lock.Lock()
		defer st.lock.Unlock()
		delete(st.streams, key)
	})
	return nil
}

func (st *beeperStreamHandler) HandleIncomingEvent(ctx context.Context, evt *event.Event) bool {
	switch evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		return st.handleSubscribeEvent(ctx, evt)
	case event.ToDeviceEncrypted:
		return st.handleEncryptedEvent(ctx, evt)
	default:
		return false
	}
}

func (st *beeperStreamHandler) handleSubscribeEvent(ctx context.Context, evt *event.Event) bool {
	subscribe := evt.Content.AsBeeperStreamSubscribe()
	if subscribe == nil {
		return true
	}
	logins, err := st.loginsForRoom(ctx, subscribe.RoomID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Str("room_id", subscribe.RoomID.String()).
			Msg("Failed to resolve user logins for stream subscribe")
		return true
	}
	for _, login := range logins {
		loginStream, ok := login.BeeperStream.(*userLoginBeeperStream)
		if !ok || loginStream == nil {
			continue
		}
		loginStream.handleSubscribe(ctx, evt.Sender, subscribe)
	}
	return true
}

func (st *beeperStreamHandler) handleEncryptedEvent(ctx context.Context, evt *event.Event) bool {
	content := evt.Content.AsEncrypted()
	if content.Algorithm != id.AlgorithmBeeperStreamAESGCM {
		return false
	}
	for _, login := range st.br.GetAllCachedUserLogins() {
		loginStream, ok := login.BeeperStream.(*userLoginBeeperStream)
		if !ok || loginStream == nil {
			continue
		}
		if loginStream.handleEncryptedSubscribe(ctx, evt, content) {
			return true
		}
	}
	zerolog.Ctx(ctx).Debug().
		Str("sender", evt.Sender.String()).
		Str("to_device_id", evt.ToDeviceID.String()).
		Msg("Ignoring custom encrypted to-device event that doesn't match an active stream")
	return true
}

func (st *userLoginBeeperStream) handleEncryptedSubscribe(ctx context.Context, evt *event.Event, content *event.EncryptedEventContent) bool {
	st.lock.Lock()
	states := make([]*streamState, 0, len(st.streams))
	for _, state := range st.streams {
		if state.descriptor == nil || state.descriptor.Encryption == nil {
			continue
		}
		if evt.ToDeviceID != "" && evt.ToDeviceID != state.descriptor.DeviceID {
			continue
		}
		states = append(states, state)
	}
	st.lock.Unlock()

	for _, state := range states {
		payload, err := decryptStreamPayload(content, state.descriptor.Encryption.Key)
		if err != nil {
			continue
		}
		switch payload.Type {
		case event.ToDeviceBeeperStreamSubscribe.Type:
			var subscribe event.BeeperStreamSubscribeEventContent
			if err = json.Unmarshal(payload.Content, &subscribe); err != nil {
				continue
			}
			if subscribe.RoomID != state.key.roomID || subscribe.EventID != state.key.eventID {
				continue
			}
			st.handleSubscribe(ctx, evt.Sender, &subscribe)
			return true
		default:
			continue
		}
	}
	return false
}

func (st *userLoginBeeperStream) handleSubscribe(ctx context.Context, sender id.UserID, subscribe *event.BeeperStreamSubscribeEventContent) {
	if subscribe == nil {
		return
	}
	user, err := st.login.Bridge.GetUserByMXID(ctx, sender)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Str("sender", sender.String()).Msg("Failed to load stream subscriber user")
		return
	} else if user == nil || !user.Permissions.SendEvents {
		zerolog.Ctx(ctx).Debug().Str("sender", sender.String()).Msg("Ignoring stream subscribe from unauthorized user")
		return
	}

	key := streamKey{roomID: subscribe.RoomID, eventID: subscribe.EventID}
	st.lock.Lock()
	state := st.streams[key]
	if state == nil || state.finished {
		st.lock.Unlock()
		return
	}
	expiry := time.Duration(subscribe.ExpiryMS) * time.Millisecond
	if expiry <= 0 {
		expiry = time.Duration(state.descriptor.ExpiryMS) * time.Millisecond
	}
	if expiry <= 0 {
		expiry = DefaultStreamExpiry
	}
	state.subscribers[streamSubscriber{userID: sender, deviceID: subscribe.DeviceID}] = time.Now().Add(expiry)
	desc := state.descriptor
	updates := append([]*event.Content(nil), state.updates...)
	st.lock.Unlock()

	for _, update := range updates {
		if err = st.sendUpdateToSubscribers(ctx, desc, update, []streamSubscriber{{userID: sender, deviceID: subscribe.DeviceID}}); err != nil {
			zerolog.Ctx(ctx).Err(err).
				Str("room_id", subscribe.RoomID.String()).
				Str("event_id", subscribe.EventID.String()).
				Str("subscriber", sender.String()).
				Msg("Failed to replay stream updates to new subscriber")
			break
		}
	}
}

func (st *userLoginBeeperStream) sendUpdateToSubscribers(ctx context.Context, descriptor *event.BeeperStreamInfo, update *event.Content, subscribers []streamSubscriber) error {
	if len(subscribers) == 0 {
		return nil
	}
	sender, err := st.handler.getSender()
	if err != nil {
		return err
	}
	eventType, content, err := st.handler.makeToDeviceContent(descriptor, event.ToDeviceBeeperStreamUpdate, update)
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
	_, err = sender.SendToDevice(ctx, eventType, req)
	return err
}

func (st *beeperStreamHandler) makeToDeviceContent(descriptor *event.BeeperStreamInfo, logicalType event.Type, payload *event.Content) (event.Type, *event.Content, error) {
	if descriptor != nil && descriptor.Encryption != nil {
		encrypted, err := encryptStreamPayload(logicalType, payload, descriptor.Encryption.Key)
		if err != nil {
			return event.Type{}, nil, err
		}
		return event.ToDeviceEncrypted, &event.Content{Parsed: encrypted}, nil
	}
	return logicalType, payload, nil
}

func (st *beeperStreamHandler) getSender() (ToDeviceSendingMatrixAPI, error) {
	sender, ok := st.br.Bot.(ToDeviceSendingMatrixAPI)
	if !ok {
		return nil, fmt.Errorf("bridge bot doesn't support to-device events")
	} else if sender.GetDeviceID() == "" {
		return nil, fmt.Errorf("bridge bot doesn't have a device ID for stream transport")
	}
	return sender, nil
}

func (st *beeperStreamHandler) isEncryptedRoom(ctx context.Context, roomID id.RoomID) (bool, error) {
	conn, ok := st.br.Matrix.(MatrixConnectorWithArbitraryRoomState)
	if !ok {
		return false, nil
	}
	evt, err := conn.GetStateEvent(ctx, roomID, event.StateEncryption, "")
	if errors.Is(err, mautrix.MNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return evt != nil, nil
}

func (st *beeperStreamHandler) loginsForRoom(ctx context.Context, roomID id.RoomID) ([]*UserLogin, error) {
	portal, err := st.br.GetPortalByMXID(ctx, roomID)
	if err != nil || portal == nil {
		return nil, err
	}
	if portal.Receiver != "" {
		login := st.br.GetCachedUserLoginByID(portal.Receiver)
		if login == nil {
			return nil, nil
		}
		return []*UserLogin{login}, nil
	}
	return st.br.GetUserLoginsInPortal(ctx, portal.PortalKey)
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

func encryptStreamPayload(logicalType event.Type, payload *event.Content, base64Key string) (*event.EncryptedEventContent, error) {
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
	gcm, err := newStreamGCM(base64Key)
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
		StreamCiphertext: []byte(base64.RawStdEncoding.EncodeToString(ciphertext)),
	}, nil
}

func decryptStreamPayload(content *event.EncryptedEventContent, base64Key string) (*streamEncryptedPayload, error) {
	iv, err := base64.RawStdEncoding.DecodeString(content.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode stream IV: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(string(content.StreamCiphertext))
	if err != nil {
		return nil, fmt.Errorf("failed to decode stream ciphertext: %w", err)
	}
	gcm, err := newStreamGCM(base64Key)
	if err != nil {
		return nil, err
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

func newStreamUpdateContent(req *PublishStreamRequest) (*event.Content, error) {
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
