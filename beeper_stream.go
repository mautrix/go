// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
    "context"
    "crypto/cipher"
    "fmt"
    "slices"
    "sync"
    "time"

    "github.com/rs/zerolog"

    "maunium.net/go/mautrix/event"
    "maunium.net/go/mautrix/id"
)

const (
    // DefaultBeeperStreamDescriptorExpiry is the default lifetime of a beeper stream descriptor.
    DefaultBeeperStreamDescriptorExpiry = 30 * time.Minute
    // DefaultBeeperStreamSubscribeExpiry is the default lifetime of a beeper stream subscription.
    DefaultBeeperStreamSubscribeExpiry = 5 * time.Minute

    defaultBeeperStreamRenewInterval = 30 * time.Second
    beeperStreamCleanupGrace         = 30 * time.Second
    beeperStreamPendingSubscribeTTL  = 5 * time.Second
    maxPendingBeeperStreamSubs       = 64
    maxBeeperStreamUpdates           = 1024
)

type BeeperStreamSubscribeRequest struct {
    RoomID   id.RoomID
    EventID  id.EventID
    UserID   id.UserID
    DeviceID id.DeviceID
    Expiry   time.Duration
}

type BeeperStreamManager struct {
    client *Client
    log    zerolog.Logger

    lock                sync.RWMutex
    authorizeSubscriber func(context.Context, *BeeperStreamSubscribeRequest) bool
    publishedStreams    map[beeperStreamKey]*beeperStreamPublished
    subscriptions       map[beeperStreamKey]*beeperStreamSubscription

    pendingLock      sync.Mutex
    pendingSubscribe []pendingSubscribeEvent

    now func() time.Time
}

type beeperStreamKey struct {
    roomID  id.RoomID
    eventID id.EventID
}

type beeperStreamSubscriber struct {
    userID   id.UserID
    deviceID id.DeviceID
}

type beeperStreamPublished struct {
    key        beeperStreamKey
    descriptor *event.BeeperStreamInfo
    updates    []*event.Content

    subscribers  map[beeperStreamSubscriber]time.Time
    inactive     bool
    cleanup      *time.Timer
    lastEviction time.Time

    gcm cipher.AEAD
}

type beeperStreamSubscription struct {
    key        beeperStreamKey
    descriptor *event.BeeperStreamInfo
    cancel     context.CancelFunc
}

type pendingSubscribeEvent struct {
    evt        *event.Event
    receivedAt time.Time
}

func (cli *Client) BeeperStreams() *BeeperStreamManager {
    if cli == nil {
        return nil
    }
    cli.beeperStreamLock.Lock()
    defer cli.beeperStreamLock.Unlock()
    if cli.beeperStream != nil {
        return cli.beeperStream
    }
    manager := &BeeperStreamManager{
        client:           cli,
        log:              cli.Log.With().Str("component", "beeper_stream").Logger(),
        publishedStreams: make(map[beeperStreamKey]*beeperStreamPublished),
        subscriptions:    make(map[beeperStreamKey]*beeperStreamSubscription),
        now:              time.Now,
    }
    cli.beeperStream = manager
    return manager
}

func (m *BeeperStreamManager) SetAuthorizeSubscriber(authorize func(context.Context, *BeeperStreamSubscribeRequest) bool) {
    if m == nil {
        return
    }
    m.lock.Lock()
    m.authorizeSubscriber = authorize
    m.lock.Unlock()
}

func (m *BeeperStreamManager) NewDescriptor(ctx context.Context, roomID id.RoomID, streamType string) (*event.BeeperStreamInfo, error) {
    if m == nil {
        return nil, fmt.Errorf("beeper stream manager is nil")
    } else if roomID == "" || streamType == "" {
        return nil, fmt.Errorf("missing beeper stream descriptor request fields")
    }
    client, err := m.requireClient(false)
    if err != nil {
        return nil, err
    }
    info := &event.BeeperStreamInfo{
        UserID:   client.UserID,
        DeviceID: client.DeviceID,
        Type:     streamType,
        ExpiryMS: DefaultBeeperStreamDescriptorExpiry.Milliseconds(),
        Status:   event.BeeperStreamStatusActive,
    }
    if m.isEncrypted(ctx, roomID) {
        info.Encryption = &event.BeeperStreamEncryptionInfo{
            Algorithm: id.AlgorithmBeeperStreamAESGCM,
            Key:       makeStreamKey(),
        }
    }
    return info, nil
}

func (m *BeeperStreamManager) Register(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error {
    if descriptor == nil {
        return fmt.Errorf("missing beeper stream descriptor")
    } else if descriptor.Status != event.BeeperStreamStatusActive {
        return fmt.Errorf("beeper stream descriptor must be active when registering")
    } else if err := validateDescriptor(descriptor); err != nil {
        return err
    }
    key := beeperStreamKey{roomID: roomID, eventID: eventID}
    state := &beeperStreamPublished{
        key:         key,
        descriptor:  cloneDescriptor(descriptor),
        subscribers: make(map[beeperStreamSubscriber]time.Time),
    }
    if descriptor.Encryption != nil {
        gcm, err := newStreamGCM(descriptor.Encryption.Key)
        if err != nil {
            return fmt.Errorf("failed to initialize beeper stream cipher: %w", err)
        }
        state.gcm = gcm
    }
    m.lock.Lock()
    if existing := m.publishedStreams[key]; existing != nil {
        if descriptorEqual(existing.descriptor, state.descriptor) {
            m.lock.Unlock()
            m.replayPendingSubscribe(ctx)
            return nil
        }
        if existing.cleanup != nil {
            existing.cleanup.Stop()
        }
    }
    m.publishedStreams[key] = state
    m.lock.Unlock()
    m.replayPendingSubscribe(ctx)
    return nil
}

func (m *BeeperStreamManager) Unregister(roomID id.RoomID, eventID id.EventID) {
    if m == nil {
        return
    }
    key := beeperStreamKey{roomID: roomID, eventID: eventID}
    m.lock.Lock()
    state := m.publishedStreams[key]
    if state == nil {
        m.lock.Unlock()
        return
    }
    state.inactive = true
    state.subscribers = nil
    if state.cleanup != nil {
        state.cleanup.Stop()
    }
    state.cleanup = time.AfterFunc(beeperStreamCleanupGrace, func() {
        m.lock.Lock()
        delete(m.publishedStreams, key)
        m.lock.Unlock()
    })
    m.lock.Unlock()
}

func (m *BeeperStreamManager) Publish(ctx context.Context, roomID id.RoomID, eventID id.EventID, delta map[string]any) error {
    update, err := newUpdateContent(roomID, eventID, delta)
    if err != nil {
        return err
    }
    key := beeperStreamKey{roomID: roomID, eventID: eventID}
    m.lock.Lock()
    state := m.publishedStreams[key]
    if state == nil {
        m.lock.Unlock()
        return fmt.Errorf("beeper stream %s/%s not found", roomID, eventID)
    } else if state.inactive {
        m.lock.Unlock()
        return fmt.Errorf("beeper stream %s/%s is inactive", roomID, eventID)
    }
    state.updates = append(state.updates, update)
    if len(state.updates) > maxBeeperStreamUpdates {
        state.updates = state.updates[len(state.updates)-maxBeeperStreamUpdates:]
    }
    descriptor := cloneDescriptor(state.descriptor)
    gcm := state.gcm
    subscribers := state.activeSubscribers(m.now())
    m.lock.Unlock()
    return m.sendUpdate(ctx, descriptor, gcm, update, subscribers)
}

func (m *BeeperStreamManager) Subscribe(ctx context.Context, roomID id.RoomID, eventID id.EventID, descriptor *event.BeeperStreamInfo) error {
    if descriptor == nil {
        return fmt.Errorf("missing beeper stream descriptor")
    } else if descriptor.Status != event.BeeperStreamStatusActive {
        return fmt.Errorf("beeper stream descriptor must be active when subscribing")
    } else if err := validateDescriptor(descriptor); err != nil {
        return err
    }
    key := beeperStreamKey{roomID: roomID, eventID: eventID}
    m.lock.Lock()
    if existing := m.subscriptions[key]; existing != nil {
        if descriptorEqual(existing.descriptor, descriptor) {
            m.lock.Unlock()
            return nil
        }
        existing.cancel()
        delete(m.subscriptions, key)
    }
    subscribeCtx := context.Background()
    if ctx != nil {
        subscribeCtx = context.WithoutCancel(ctx)
    }
    subCtx, cancel := context.WithCancel(subscribeCtx)
    sub := &beeperStreamSubscription{
        key:        key,
        descriptor: cloneDescriptor(descriptor),
        cancel:     cancel,
    }
    m.subscriptions[key] = sub
    m.lock.Unlock()

    go m.runSubscriptionLoop(subCtx, sub)
    return nil
}

func (m *BeeperStreamManager) Unsubscribe(roomID id.RoomID, eventID id.EventID) {
    if m == nil {
        return
    }
    key := beeperStreamKey{roomID: roomID, eventID: eventID}
    m.lock.Lock()
    sub := m.subscriptions[key]
    if sub != nil {
        delete(m.subscriptions, key)
    }
    m.lock.Unlock()
    if sub != nil {
        sub.cancel()
    }
}

func (m *BeeperStreamManager) runSubscriptionLoop(ctx context.Context, sub *beeperStreamSubscription) {
    expiry := resolveSubscribeExpiry(sub.descriptor, DefaultBeeperStreamSubscribeExpiry)
    renewInterval := max(expiry/2, defaultBeeperStreamRenewInterval)
    if err := m.sendSubscribe(ctx, sub.key, sub.descriptor, expiry); err != nil && ctx.Err() == nil {
        m.log.Warn().Err(err).
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
            if err := m.sendSubscribe(ctx, sub.key, sub.descriptor, expiry); err != nil && ctx.Err() == nil {
                m.log.Warn().Err(err).
                    Stringer("room_id", sub.key.roomID).
                    Stringer("event_id", sub.key.eventID).
                    Msg("Failed to renew beeper stream subscribe")
            }
        }
    }
}

func (m *BeeperStreamManager) sendSubscribe(ctx context.Context, key beeperStreamKey, descriptor *event.BeeperStreamInfo, expiry time.Duration) error {
    client, err := m.requireClient(true)
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
    // Subscribers follow the publisher-provided descriptor wire contract.
    if descriptor.Encryption != nil {
        payload, err := stripSubscribeRouting(client.DeviceID, expiry.Milliseconds())
        if err != nil {
            return err
        }
		encrypted, err := encryptLogicalEvent(event.ToDeviceBeeperStreamSubscribe, payload, key.roomID, key.eventID, descriptor.Encryption.Key)
        if err != nil {
            return err
        }
        eventType = event.ToDeviceBeeperStreamEncrypted
        content = &event.Content{Parsed: encrypted}
    }
    _, err = client.SendToDevice(ctx, eventType, &ReqSendToDevice{
        Messages: map[id.UserID]map[id.DeviceID]*event.Content{
            descriptor.UserID: {
                targetDevice: content,
            },
        },
    })
    return err
}

func (m *BeeperStreamManager) handleToDeviceEvent(ctx context.Context, evt *event.Event) bool {
    if m == nil || evt == nil {
        return false
    }
    switch evt.Type {
    case event.ToDeviceBeeperStreamSubscribe:
        return m.handleSubscribeEvent(ctx, evt)
    case event.ToDeviceBeeperStreamUpdate:
        return m.handlePlainUpdateEvent(evt)
    case event.ToDeviceBeeperStreamEncrypted:
        return m.handleEncryptedEvent(ctx, evt)
    default:
        return false
    }
}

func (m *BeeperStreamManager) handleSubscribeEvent(ctx context.Context, evt *event.Event) bool {
    if m.isForDifferentUser(evt) {
        return true
    }
    subscribe := evt.Content.AsBeeperStreamSubscribe()
    if subscribe.RoomID == "" || subscribe.EventID == "" {
        return true
    }
    if m.handleSubscribe(ctx, evt.Sender, subscribe) {
        return true
    }
    m.queuePendingSubscribe(ctx, evt)
    return true
}

func (m *BeeperStreamManager) handlePlainUpdateEvent(evt *event.Event) bool {
    update := evt.Content.AsBeeperStreamUpdate()
    if update.RoomID == "" || update.EventID == "" {
        return true
    }
    key := beeperStreamKey{roomID: update.RoomID, eventID: update.EventID}
    m.lock.RLock()
    sub := m.subscriptions[key]
    m.lock.RUnlock()
    if sub != nil && sub.descriptor.UserID != "" && evt.Sender != "" && evt.Sender != sub.descriptor.UserID {
        m.log.Warn().
            Stringer("sender", evt.Sender).
            Stringer("expected_user_id", sub.descriptor.UserID).
            Stringer("room_id", update.RoomID).
            Stringer("event_id", update.EventID).
            Msg("Beeper stream update from unexpected sender, dropping")
        return true
    }
    return false
}

func (m *BeeperStreamManager) handleEncryptedEvent(ctx context.Context, evt *event.Event) bool {
    content := evt.Content.AsBeeperStreamEncrypted()
    if content.RoomID == "" || content.EventID == "" || content.Ciphertext == "" {
        return true
    }
    key := beeperStreamKey{roomID: content.RoomID, eventID: content.EventID}
    m.lock.RLock()
    published := m.publishedStreams[key]
    sub := m.subscriptions[key]
    m.lock.RUnlock()
    if published != nil {
        return m.handleEncryptedForPublisher(ctx, evt, content, published)
    }
    if sub != nil {
        return m.handleEncryptedForSubscriber(ctx, evt, content, sub)
    }
    m.queuePendingSubscribe(ctx, evt)
    return true
}

func (m *BeeperStreamManager) handleEncryptedForPublisher(ctx context.Context, evt *event.Event, content *event.BeeperStreamEncryptedEventContent, state *beeperStreamPublished) bool {
    if state.gcm == nil {
        return true
    }
    logicalType, parsedContent, err := decryptLogicalEvent(content, state.descriptor.Encryption.Key)
    if err != nil {
        zerolog.Ctx(ctx).Debug().Err(err).Msg("Failed to decrypt custom encrypted beeper stream event")
        return true
    }
    if logicalType != event.ToDeviceBeeperStreamSubscribe {
        return true
    }
    evt.Type = logicalType
    evt.Type.Class = event.ToDeviceEventType
    evt.Content = *parsedContent
    return m.handleSubscribeEvent(ctx, evt)
}

func (m *BeeperStreamManager) handleEncryptedForSubscriber(ctx context.Context, evt *event.Event, content *event.BeeperStreamEncryptedEventContent, sub *beeperStreamSubscription) bool {
    logicalType, parsedContent, err := decryptLogicalEvent(content, sub.descriptor.Encryption.Key)
    if err != nil {
        m.log.Debug().Err(err).
            Stringer("room_id", content.RoomID).
            Stringer("event_id", content.EventID).
            Msg("Failed to decrypt beeper stream event")
        return true
    }
    if logicalType != event.ToDeviceBeeperStreamUpdate {
        return true
    }
    update := parsedContent.AsBeeperStreamUpdate()
    if update.RoomID != sub.key.roomID || update.EventID != sub.key.eventID {
        return true
    }
    if evt.Sender != sub.descriptor.UserID {
        m.log.Warn().
            Stringer("sender", evt.Sender).
            Stringer("expected_user_id", sub.descriptor.UserID).
            Stringer("room_id", update.RoomID).
            Stringer("event_id", update.EventID).
            Msg("Encrypted beeper stream update from unexpected sender, dropping")
        return true
    }
    evt.Type = logicalType
    evt.Type.Class = event.ToDeviceEventType
    evt.Content = *parsedContent
    return false
}

func (m *BeeperStreamManager) handleSubscribe(ctx context.Context, sender id.UserID, subscribe *event.BeeperStreamSubscribeEventContent) bool {
    if subscribe == nil {
        return false
    }
    key := beeperStreamKey{roomID: subscribe.RoomID, eventID: subscribe.EventID}
    m.lock.Lock()
    state := m.publishedStreams[key]
    if state == nil {
        m.lock.Unlock()
        return false
    } else if state.inactive {
        m.lock.Unlock()
        return true
    }
    authFunc := m.authorizeSubscriber
    authReq := &BeeperStreamSubscribeRequest{
        RoomID:   subscribe.RoomID,
        EventID:  subscribe.EventID,
        UserID:   sender,
        DeviceID: subscribe.DeviceID,
        Expiry:   time.Duration(subscribe.ExpiryMS) * time.Millisecond,
    }
    if authFunc != nil {
        m.lock.Unlock()
        if !authFunc(ctx, authReq) {
            return true
        }
        m.lock.Lock()
        state = m.publishedStreams[key]
        if state == nil || state.inactive {
            m.lock.Unlock()
            return true
        }
    }
    expiry := resolveSubscribeExpiry(state.descriptor, authReq.Expiry)
    subscriber := beeperStreamSubscriber{userID: sender, deviceID: subscribe.DeviceID}
    state.subscribers[subscriber] = m.now().Add(expiry)
    descriptor := cloneDescriptor(state.descriptor)
    gcm := state.gcm
    updates := slices.Clone(state.updates)
    m.lock.Unlock()

    for _, update := range updates {
        if err := m.sendUpdate(ctx, descriptor, gcm, update, []beeperStreamSubscriber{subscriber}); err != nil {
            m.lock.Lock()
            state = m.publishedStreams[key]
            if state != nil {
                delete(state.subscribers, subscriber)
            }
            m.lock.Unlock()
            return true
        }
    }
    return true
}

func (m *BeeperStreamManager) sendUpdate(ctx context.Context, descriptor *event.BeeperStreamInfo, gcm cipher.AEAD, update *event.Content, subscribers []beeperStreamSubscriber) error {
    if len(subscribers) == 0 {
        return nil
    }
    client, err := m.requireClient(false)
    if err != nil {
        return err
    }
    eventType := event.ToDeviceBeeperStreamUpdate
    content := update
    if descriptor != nil && descriptor.Encryption != nil && gcm != nil {
        payload, err := stripUpdateRouting(update)
        if err != nil {
            return err
        }
        updateInfo := update.AsBeeperStreamUpdate()
		encrypted, encErr := encryptLogicalEvent(event.ToDeviceBeeperStreamUpdate, payload, updateInfo.RoomID, updateInfo.EventID, descriptor.Encryption.Key)
        if encErr != nil {
            return encErr
        }
        eventType = event.ToDeviceBeeperStreamEncrypted
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

func (m *BeeperStreamManager) queuePendingSubscribe(ctx context.Context, evt *event.Event) {
    now := m.now()
    m.pendingLock.Lock()
    m.pendingSubscribe = append(m.pendingSubscribe, pendingSubscribeEvent{
        evt:        evt,
        receivedAt: now,
    })
    if len(m.pendingSubscribe) > maxPendingBeeperStreamSubs {
        m.pendingSubscribe = m.pendingSubscribe[len(m.pendingSubscribe)-maxPendingBeeperStreamSubs:]
    }
    m.pendingLock.Unlock()
    zerolog.Ctx(ctx).Debug().
        Int("pending_subscribes", len(m.pendingSubscribe)).
        Stringer("sender", evt.Sender).
        Str("event_type", evt.Type.Type).
        Msg("Queued subscribe for possible future beeper stream registration")
}

func (m *BeeperStreamManager) replayPendingSubscribe(ctx context.Context) {
    now := m.now()
    m.pendingLock.Lock()
    if len(m.pendingSubscribe) == 0 {
        m.pendingLock.Unlock()
        return
    }
    pending := slices.Clone(m.pendingSubscribe)
    m.pendingLock.Unlock()
    consumed := make(map[*event.Event]struct{})
    for _, candidate := range pending {
        if candidate.evt == nil || now.Sub(candidate.receivedAt) > beeperStreamPendingSubscribeTTL {
            continue
        }
        if m.tryPendingSubscribe(ctx, candidate.evt) {
            consumed[candidate.evt] = struct{}{}
        }
    }
    if len(consumed) == 0 {
        return
    }
    m.pendingLock.Lock()
    var filtered []pendingSubscribeEvent
    for _, candidate := range m.pendingSubscribe {
        if candidate.evt == nil || now.Sub(candidate.receivedAt) > beeperStreamPendingSubscribeTTL {
            continue
        }
        if _, ok := consumed[candidate.evt]; ok {
            continue
        }
        filtered = append(filtered, candidate)
    }
    m.pendingSubscribe = filtered
    m.pendingLock.Unlock()
}

func (m *BeeperStreamManager) tryPendingSubscribe(ctx context.Context, evt *event.Event) bool {
    switch evt.Type {
    case event.ToDeviceBeeperStreamSubscribe:
        subscribe := evt.Content.AsBeeperStreamSubscribe()
        if subscribe.RoomID == "" || subscribe.EventID == "" {
            return false
        }
        return m.handleSubscribe(ctx, evt.Sender, subscribe)
    case event.ToDeviceBeeperStreamEncrypted:
        content := evt.Content.AsBeeperStreamEncrypted()
        if content.RoomID == "" || content.EventID == "" {
            return false
        }
        key := beeperStreamKey{roomID: content.RoomID, eventID: content.EventID}
        m.lock.RLock()
        state := m.publishedStreams[key]
        m.lock.RUnlock()
        if state == nil {
            return false
        }
        return m.handleEncryptedForPublisher(ctx, evt, content, state)
    default:
        return false
    }
}

func (m *BeeperStreamManager) isEncrypted(ctx context.Context, roomID id.RoomID) bool {
    if m == nil || m.client == nil || m.client.StateStore == nil {
        return false
    }
    encrypted, err := m.client.StateStore.IsEncrypted(ctx, roomID)
    return err == nil && encrypted
}

func (m *BeeperStreamManager) isForDifferentUser(evt *event.Event) bool {
    if m == nil || m.client == nil || evt == nil {
        return false
    }
    return evt.ToUserID != "" && evt.ToUserID != m.client.UserID
}

func (m *BeeperStreamManager) requireClient(requireDevice bool) (*Client, error) {
    if m == nil || m.client == nil {
        return nil, fmt.Errorf("beeper stream manager doesn't have a client")
    } else if m.client.UserID == "" {
        return nil, fmt.Errorf("beeper stream client isn't logged in")
    } else if requireDevice && m.client.DeviceID == "" {
        return nil, fmt.Errorf("beeper stream client doesn't have a device ID")
    }
    return m.client, nil
}

func (state *beeperStreamPublished) activeSubscribers(now time.Time) []beeperStreamSubscriber {
    var active []beeperStreamSubscriber
    doEvict := now.Sub(state.lastEviction) >= beeperStreamCleanupGrace
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

func resolveSubscribeExpiry(descriptor *event.BeeperStreamInfo, fallback time.Duration) time.Duration {
    if fallback <= 0 {
        fallback = DefaultBeeperStreamSubscribeExpiry
    }
    if descriptor != nil && descriptor.ExpiryMS > 0 {
        descriptorExpiry := time.Duration(descriptor.ExpiryMS) * time.Millisecond
        if descriptorExpiry < fallback {
            return descriptorExpiry
        }
    }
    return fallback
}

func validateDescriptor(info *event.BeeperStreamInfo) error {
    if info == nil {
        return fmt.Errorf("missing beeper stream descriptor")
    } else if info.UserID == "" || info.Type == "" {
        return fmt.Errorf("missing beeper stream descriptor fields")
    }
    switch info.Status {
    case event.BeeperStreamStatusActive, event.BeeperStreamStatusComplete, event.BeeperStreamStatusCancelled:
    default:
        return fmt.Errorf("invalid beeper stream status %q", info.Status)
    }
    if info.Encryption == nil {
        return nil
    }
    if info.Encryption.Algorithm != id.AlgorithmBeeperStreamAESGCM {
        return fmt.Errorf("unsupported beeper stream encryption algorithm %q", info.Encryption.Algorithm)
    } else if info.Encryption.Key == "" {
        return fmt.Errorf("missing beeper stream encryption key")
    }
    return nil
}

func descriptorEqual(a, b *event.BeeperStreamInfo) bool {
    switch {
    case a == nil || b == nil:
        return a == b
    case a.UserID != b.UserID || a.DeviceID != b.DeviceID || a.Type != b.Type || a.ExpiryMS != b.ExpiryMS || a.Status != b.Status:
        return false
    case a.Encryption == nil || b.Encryption == nil:
        return a.Encryption == b.Encryption
    default:
        return a.Encryption.Algorithm == b.Encryption.Algorithm &&
            a.Encryption.Key == b.Encryption.Key
    }
}

func cloneDescriptor(info *event.BeeperStreamInfo) *event.BeeperStreamInfo {
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
