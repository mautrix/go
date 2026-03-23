// Copyright (c) 2026 Batuhan İçöz
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package beeperstream

import (
	"bytes"
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
	encryptedPubl    map[string]streamKey
	subscriptions    map[streamKey]*subscription
	encryptedSubs    map[string]streamKey

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
		encryptedPubl:    make(map[string]streamKey),
		subscriptions:    make(map[streamKey]*subscription),
		encryptedSubs:    make(map[string]streamKey),
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
	on(event.ToDeviceBeeperStreamSubscribe, h.handleSubscribeEvent)
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
		sub.cancel()
		delete(h.subscriptions, key)
	}
	clear(h.encryptedSubs)
	for key, state := range h.publishedStreams {
		if state.cleanup != nil {
			state.cleanup.Stop()
		}
		delete(h.publishedStreams, key)
	}
	clear(h.encryptedPubl)
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
			Algorithm: id.AlgorithmBeeperStreamV1,
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
	if len(evt.Content.VeryRaw) > 0 && evt.Content.Raw == nil {
		_ = json.Unmarshal(evt.Content.VeryRaw, &evt.Content.Raw)
	}
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
	if content.Algorithm != id.AlgorithmBeeperStreamV1 {
		return nil
	}
	if content.StreamID == "" || len(content.MegolmCiphertext) == 0 {
		return nil
	}
	h.lock.RLock()
	publishedKey, hasPublished := h.encryptedPubl[content.StreamID]
	published := h.publishedStreams[publishedKey]
	subKey, hasSub := h.encryptedSubs[content.StreamID]
	sub := h.subscriptions[subKey]
	h.lock.RUnlock()
	if hasPublished && published != nil {
		return h.handleEncryptedForPublisher(ctx, evt, publishedKey, published)
	}
	if hasSub && sub != nil {
		return h.handleEncryptedForSubscriber(ctx, evt, subKey, sub)
	}
	h.queuePendingSubscribe(ctx, evt)
	return nil
}

func decryptedLogicalEvent(ctx context.Context, evt *event.Event, key []byte, expectedKey streamKey, expectedTypes ...event.Type) *event.Event {
	encrypted := evt.Content.AsEncrypted()
	logicalType, payload, err := decryptLogicalEvent(&evt.Content, key)
	if err != nil {
		zerolog.Ctx(ctx).Debug().Err(err).
			Str("stream_id", encrypted.StreamID).
			Msg("Failed to decrypt beeper stream event")
		return nil
	}
	if len(expectedTypes) > 0 && !containsType(expectedTypes, logicalType) {
		return nil
	}
	parsed, err := contentFromRawJSON(payload)
	if err != nil || parsed.ParseRaw(logicalType) != nil {
		return nil
	}
	if !validateLogicalRouting(parsed, logicalType, expectedKey.roomID, expectedKey.eventID) {
		return nil
	}
	normalized := *evt
	normalized.RoomID = expectedKey.roomID
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

func contentFromRawJSON(veryRaw json.RawMessage) (*event.Content, error) {
	content := &event.Content{VeryRaw: append(json.RawMessage(nil), veryRaw...)}
	if len(content.VeryRaw) == 0 {
		content.VeryRaw = []byte("{}")
	}
	if err := json.Unmarshal(content.VeryRaw, &content.Raw); err != nil {
		return nil, err
	}
	if content.Raw == nil {
		content.Raw = make(map[string]any)
	}
	return content, nil
}

func marshalContent(content *event.Content) (json.RawMessage, error) {
	if content == nil {
		return json.RawMessage(`{}`), nil
	}
	raw, err := content.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), raw...), nil
}

func normalizeUpdateContent(roomID id.RoomID, eventID id.EventID, content map[string]any) (*event.Content, error) {
	if roomID == "" || eventID == "" {
		return nil, fmt.Errorf("missing beeper stream identifiers")
	}
	raw := maps.Clone(content)
	if _, ok := raw["room_id"]; ok {
		return nil, fmt.Errorf("beeper stream payload may not override room_id")
	} else if _, ok := raw["event_id"]; ok {
		return nil, fmt.Errorf("beeper stream payload may not override event_id")
	}
	raw["room_id"] = roomID
	raw["event_id"] = eventID
	return contentFromRawMap(raw)
}

func containsType(types []event.Type, want event.Type) bool {
	for _, candidate := range types {
		if candidate == want {
			return true
		}
	}
	return false
}

func validateLogicalRouting(content *event.Content, evtType event.Type, roomID id.RoomID, eventID id.EventID) bool {
	switch evtType {
	case event.ToDeviceBeeperStreamSubscribe:
		subscribe := content.AsBeeperStreamSubscribe()
		return subscribe.RoomID == roomID && subscribe.EventID == eventID
	case event.ToDeviceBeeperStreamUpdate:
		update := content.AsBeeperStreamUpdate()
		return update.RoomID == roomID && update.EventID == eventID
	default:
		return false
	}
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
		return min(time.Duration(descriptor.ExpiryMS)*time.Millisecond, fallback)
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
			bytes.Equal(a.Encryption.Key, b.Encryption.Key)
	}
}
