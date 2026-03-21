// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package beeperstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	// DefaultDescriptorExpiry is the default lifetime of a beeper stream descriptor.
	DefaultDescriptorExpiry = 30 * time.Minute
	// DefaultSubscribeExpiry is the default lifetime of a beeper stream subscription.
	DefaultSubscribeExpiry = 5 * time.Minute

	defaultRenewInterval      = 30 * time.Second
	cleanupGrace              = 30 * time.Second
	pendingSubscribeTTL       = 5 * time.Second
	maxPendingSubscriptions   = 64
	maxStreamUpdatesPerStream = 1024
)

type Helper struct {
	client *mautrix.Client
	log    zerolog.Logger

	lock             sync.RWMutex
	publishedStreams map[streamKey]*publishedStream
	subscriptions    map[streamKey]*subscription

	pendingLock      sync.Mutex
	pendingSubscribe []pendingSubscribeEvent

	initLock    sync.Mutex
	initialized bool
	closed      atomic.Bool

	now func() time.Time
}

type streamKey struct {
	roomID  id.RoomID
	eventID id.EventID
}

func New(client *mautrix.Client) (*Helper, error) {
	if client == nil {
		return nil, fmt.Errorf("beeper stream client is nil")
	}
	return &Helper{
		client:           client,
		log:              client.Log.With().Str("component", "beeper_stream").Logger(),
		publishedStreams: make(map[streamKey]*publishedStream),
		subscriptions:    make(map[streamKey]*subscription),
		now:              time.Now,
	}, nil
}

// Init attaches beeper stream handling to a normal /sync-based client.
func (h *Helper) Init(_ context.Context) error {
	if h == nil {
		return fmt.Errorf("beeper stream helper is nil")
	} else if h.closed.Load() {
		return fmt.Errorf("beeper stream helper is closed")
	}
	h.initLock.Lock()
	defer h.initLock.Unlock()
	if h.initialized {
		return nil
	}
	syncer, ok := h.client.Syncer.(mautrix.ExtensibleSyncer)
	if !ok {
		return fmt.Errorf("the client syncer must implement ExtensibleSyncer")
	}
	dispatcher, ok := h.client.Syncer.(mautrix.DispatchableSyncer)
	if !ok {
		return fmt.Errorf("the client syncer must implement DispatchableSyncer")
	}
	h.registerIngressAdapter(
		func(evtType event.Type, handler func(context.Context, *event.Event)) {
			syncer.OnEventType(evtType, handler)
		},
		dispatcher.Dispatch,
	)
	h.initialized = true
	return nil
}

// InitAppservice attaches beeper stream handling to an appservice event processor.
func (h *Helper) InitAppservice(_ context.Context, ep interface {
	On(event.Type, func(context.Context, *event.Event))
	Dispatch(context.Context, *event.Event)
}) error {
	if h == nil {
		return fmt.Errorf("beeper stream helper is nil")
	} else if h.closed.Load() {
		return fmt.Errorf("beeper stream helper is closed")
	} else if ep == nil {
		return fmt.Errorf("beeper stream appservice event processor is nil")
	}
	h.initLock.Lock()
	defer h.initLock.Unlock()
	if h.initialized {
		return nil
	}
	h.registerIngressAdapter(ep.On, ep.Dispatch)
	h.initialized = true
	return nil
}

func (h *Helper) registerIngressAdapter(
	on func(event.Type, func(context.Context, *event.Event)),
	dispatch func(context.Context, *event.Event),
) {
	on(event.ToDeviceBeeperStreamSubscribe, func(ctx context.Context, evt *event.Event) {
		h.handleEvent(ctx, evt)
	})
	on(event.ToDeviceEncrypted, func(ctx context.Context, evt *event.Event) {
		if normalized := h.handleEvent(ctx, evt); normalized != nil && dispatch != nil {
			dispatch(ctx, normalized)
		}
	})
}

func (h *Helper) Close() error {
	if h == nil || !h.closed.CompareAndSwap(false, true) {
		return nil
	}

	h.lock.Lock()
	for key, sub := range h.subscriptions {
		if sub != nil {
			sub.cancel()
		}
		delete(h.subscriptions, key)
	}
	for key, state := range h.publishedStreams {
		if state != nil && state.cleanup != nil {
			state.cleanup.Stop()
		}
		delete(h.publishedStreams, key)
	}
	h.lock.Unlock()

	h.pendingLock.Lock()
	h.pendingSubscribe = nil
	h.pendingLock.Unlock()

	return nil
}

func (h *Helper) NewDescriptor(ctx context.Context, roomID id.RoomID, streamType string) (*event.BeeperStreamInfo, error) {
	if h == nil {
		return nil, fmt.Errorf("beeper stream helper is nil")
	} else if h.closed.Load() {
		return nil, fmt.Errorf("beeper stream helper is closed")
	} else if roomID == "" || streamType == "" {
		return nil, fmt.Errorf("missing beeper stream descriptor request fields")
	}
	client, err := h.requireClient(false)
	if err != nil {
		return nil, err
	}
	info := &event.BeeperStreamInfo{
		UserID:   client.UserID,
		DeviceID: client.DeviceID,
		Type:     streamType,
		ExpiryMS: DefaultDescriptorExpiry.Milliseconds(),
	}
	if h.isEncrypted(ctx, roomID) {
		info.Encryption = &event.BeeperStreamEncryptionInfo{
			Algorithm: id.AlgorithmBeeperStreamAESGCM,
			Key:       makeStreamKey(),
		}
	}
	return info, nil
}

func (h *Helper) HandleSyncResponse(ctx context.Context, resp *mautrix.RespSync) []*event.Event {
	if h == nil || resp == nil {
		return nil
	}
	var normalized []*event.Event
	for _, evt := range resp.ToDevice.Events {
		prepareToDeviceEvent(evt)
		if evt := h.handleEvent(ctx, evt); evt != nil {
			normalized = append(normalized, evt)
		}
	}
	return normalized
}

func prepareToDeviceEvent(evt *event.Event) {
	if evt == nil {
		return
	}
	evt.Type.Class = event.ToDeviceEventType
	if evt.Content.Parsed != nil || len(evt.Content.VeryRaw) == 0 {
		return
	}
	err := evt.Content.ParseRaw(evt.Type)
	if err != nil && !errors.Is(err, event.ErrContentAlreadyParsed) {
		evt.Content.Parsed = nil
	}
}

func (h *Helper) handleEvent(ctx context.Context, evt *event.Event) *event.Event {
	if h == nil || evt == nil || h.closed.Load() || h.isForDifferentTarget(evt) {
		return nil
	}
	switch evt.Type {
	case event.ToDeviceBeeperStreamSubscribe:
		h.handleSubscribeEvent(ctx, evt)
	case event.ToDeviceEncrypted:
		return h.handleEncryptedEvent(ctx, evt)
	}
	return nil
}

func (h *Helper) handleEncryptedEvent(ctx context.Context, evt *event.Event) *event.Event {
	content := evt.Content.AsEncrypted()
	if !content.IsBeeperStream() {
		return nil
	}
	key := streamKey{roomID: content.RoomID, eventID: content.EventID}
	h.lock.RLock()
	published := h.publishedStreams[key]
	sub := h.subscriptions[key]
	h.lock.RUnlock()
	if published != nil {
		return h.handleEncryptedForPublisher(ctx, evt, content, published)
	}
	if sub != nil {
		return h.handleEncryptedForSubscriber(ctx, evt, content, sub)
	}
	h.queuePendingSubscribe(ctx, evt)
	return nil
}

func decryptedLogicalEvent(ctx context.Context, evt *event.Event, encrypted *event.EncryptedEventContent, base64Key string, expectedType event.Type) *event.Event {
	logicalType, payload, err := decryptLogicalEvent(encrypted, base64Key)
	if err != nil {
		zerolog.Ctx(ctx).Debug().Err(err).
			Stringer("room_id", encrypted.RoomID).
			Stringer("event_id", encrypted.EventID).
			Msg("Failed to decrypt beeper stream event")
		return nil
	}
	if logicalType != expectedType {
		return nil
	}
	var raw map[string]any
	if err = json.Unmarshal(payload, &raw); err != nil {
		return nil
	}
	parsed, err := contentFromRawMap(addStreamRouting(raw, encrypted.RoomID, encrypted.EventID))
	if err != nil || parsed.ParseRaw(logicalType) != nil {
		return nil
	}
	normalized := *evt
	normalized.RoomID = encrypted.RoomID
	normalized.Type = logicalType
	normalized.Type.Class = event.ToDeviceEventType
	normalized.Content = *parsed
	return &normalized
}

func rawMapFromContent(content *event.Content) (map[string]any, error) {
	if content == nil {
		return map[string]any{}, nil
	}
	if content.Raw != nil {
		return maps.Clone(content.Raw), nil
	}
	if len(content.VeryRaw) == 0 {
		return map[string]any{}, nil
	}
	var raw map[string]any
	err := json.Unmarshal(content.VeryRaw, &raw)
	if raw == nil {
		raw = make(map[string]any)
	}
	return raw, err
}

func contentFromRawMap(raw map[string]any) (*event.Content, error) {
	if raw == nil {
		raw = make(map[string]any)
	}
	veryRaw, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	return &event.Content{VeryRaw: veryRaw, Raw: maps.Clone(raw)}, nil
}

func addStreamRouting(raw map[string]any, roomID id.RoomID, eventID id.EventID) map[string]any {
	withRouting := maps.Clone(raw)
	if withRouting == nil {
		withRouting = make(map[string]any, 2)
	}
	withRouting["room_id"] = roomID
	withRouting["event_id"] = eventID
	return withRouting
}

func removeStreamRouting(raw map[string]any) map[string]any {
	withoutRouting := maps.Clone(raw)
	if withoutRouting == nil {
		return make(map[string]any)
	}
	delete(withoutRouting, "room_id")
	delete(withoutRouting, "event_id")
	return withoutRouting
}

func (h *Helper) isEncrypted(ctx context.Context, roomID id.RoomID) bool {
	if h == nil || h.client == nil || h.client.StateStore == nil {
		return false
	}
	encrypted, err := h.client.StateStore.IsEncrypted(ctx, roomID)
	return err == nil && encrypted
}

func (h *Helper) isForDifferentTarget(evt *event.Event) bool {
	if h == nil || h.client == nil || evt == nil {
		return false
	}
	return (evt.ToUserID != "" && evt.ToUserID != h.client.UserID) ||
		(evt.ToDeviceID != "" && evt.ToDeviceID != h.client.DeviceID)
}

func (h *Helper) requireClient(requireDevice bool) (*mautrix.Client, error) {
	if h == nil || h.client == nil {
		return nil, fmt.Errorf("beeper stream helper doesn't have a client")
	} else if h.client.UserID == "" {
		return nil, fmt.Errorf("beeper stream client isn't logged in")
	} else if requireDevice && h.client.DeviceID == "" {
		return nil, fmt.Errorf("beeper stream client doesn't have a device ID")
	}
	return h.client, nil
}

func resolveSubscribeExpiry(descriptor *event.BeeperStreamInfo, fallback time.Duration) time.Duration {
	if fallback <= 0 {
		fallback = DefaultSubscribeExpiry
	}
	if descriptor != nil && descriptor.ExpiryMS > 0 {
		descriptorExpiry := time.Duration(descriptor.ExpiryMS) * time.Millisecond
		if descriptorExpiry < fallback {
			return descriptorExpiry
		}
	}
	return fallback
}

func descriptorEqual(a, b *event.BeeperStreamInfo) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	case a.UserID != b.UserID || a.DeviceID != b.DeviceID || a.Type != b.Type || a.ExpiryMS != b.ExpiryMS:
		return false
	case a.Encryption == nil || b.Encryption == nil:
		return a.Encryption == b.Encryption
	default:
		return a.Encryption.Algorithm == b.Encryption.Algorithm &&
			a.Encryption.Key == b.Encryption.Key
	}
}
