// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// accountDataSyncer runs a /sync loop as a double-puppeted user to receive
// room account data changes (m.marked_unread, m.tag, com.beeper.mute).
// This is necessary because Synapse does not forward account data events
// to appservices via the transaction API.
type accountDataSyncer struct {
	br     *Connector
	userID id.UserID
	client *mautrix.Client
	log    zerolog.Logger

	cancelSync context.CancelFunc
	syncDone   sync.WaitGroup

	// recentlySet tracks account data content recently set by the bridge itself
	// to avoid infinite loops. Key is "roomID:eventType", value is the last
	// JSON content that was set. When a sync event arrives with matching content,
	// it is recognized as a bridge echo and skipped.
	recentlySet     map[string]*sentAccountData
	recentlySetLock sync.Mutex
}

type sentAccountData struct {
	content json.RawMessage
	sentAt  time.Time
}

var accountDataTypes = []event.Type{
	event.AccountDataMarkedUnread,
	event.AccountDataRoomTags,
	event.AccountDataBeeperMute,
}

func (br *Connector) StartAccountDataSync(userID id.UserID, source *mautrix.Client) {
	br.stopAccountDataSync(userID)

	// Create a separate client for the sync loop so we don't interfere
	// with the double puppet intent's client.
	syncClient, err := mautrix.NewClient(source.HomeserverURL.String(), userID, source.AccessToken)
	if err != nil {
		br.Bridge.Log.Err(err).Stringer("user_id", userID).Msg("Failed to create account data sync client")
		return
	}
	syncClient.SetAppServiceUserID = source.SetAppServiceUserID

	syncer := &accountDataSyncer{
		br:          br,
		userID:      userID,
		client:      syncClient,
		log:         br.Bridge.Log.With().Str("component", "account_data_sync").Stringer("user_id", userID).Logger(),
		recentlySet: make(map[string]*sentAccountData),
	}

	br.accountDataSyncersLock.Lock()
	br.accountDataSyncers[userID] = syncer
	br.accountDataSyncersLock.Unlock()

	syncer.Start()
}

func (br *Connector) stopAccountDataSync(userID id.UserID) {
	br.accountDataSyncersLock.Lock()
	existing, ok := br.accountDataSyncers[userID]
	if ok {
		delete(br.accountDataSyncers, userID)
	}
	br.accountDataSyncersLock.Unlock()
	if ok {
		existing.Stop()
	}
}

func (br *Connector) StopAccountDataSync(userID id.UserID) {
	br.stopAccountDataSync(userID)
}

func (br *Connector) StopAllAccountDataSyncers() {
	br.accountDataSyncersLock.Lock()
	syncers := make(map[id.UserID]*accountDataSyncer, len(br.accountDataSyncers))
	maps.Copy(syncers, br.accountDataSyncers)
	br.accountDataSyncers = make(map[id.UserID]*accountDataSyncer)
	br.accountDataSyncersLock.Unlock()
	for _, syncer := range syncers {
		syncer.Stop()
	}
}

// MarkAccountDataSent records that the bridge set account data for a room,
// so the sync loop can skip the resulting event to avoid loops.
// The content parameter is the JSON-serialized content that was set.
func (br *Connector) MarkAccountDataSent(userID id.UserID, roomID id.RoomID, evtType string, content json.RawMessage) {
	br.accountDataSyncersLock.Lock()
	syncer, ok := br.accountDataSyncers[userID]
	br.accountDataSyncersLock.Unlock()
	if ok {
		syncer.markSent(roomID, evtType, content)
	}
}

func (s *accountDataSyncer) markSent(roomID id.RoomID, evtType string, content json.RawMessage) {
	key := string(roomID) + ":" + evtType
	s.recentlySetLock.Lock()
	s.recentlySet[key] = &sentAccountData{content: content, sentAt: time.Now()}
	s.recentlySetLock.Unlock()
}

func (s *accountDataSyncer) wasRecentlySent(roomID id.RoomID, evtType string, incomingContent json.RawMessage) bool {
	key := string(roomID) + ":" + evtType
	s.recentlySetLock.Lock()
	defer s.recentlySetLock.Unlock()
	stored, ok := s.recentlySet[key]
	if !ok {
		return false
	}
	// Clean up entries older than 10 minutes to prevent memory leaks.
	if time.Since(stored.sentAt) >= 10*time.Minute {
		delete(s.recentlySet, key)
		return false
	}
	// If content was provided when marking, compare it with the incoming event.
	// This correctly handles delayed sync deliveries regardless of timing.
	if stored.content != nil {
		return bytes.Equal(stored.content, incomingContent)
	}
	// Fallback for event types where content isn't tracked (e.g. tags):
	// use time-based dedup within a short window.
	return time.Since(stored.sentAt) < 30*time.Second
}

func (s *accountDataSyncer) Start() {
	s.syncDone.Add(1)
	go s.syncLoop()
}

func (s *accountDataSyncer) Stop() {
	if s.cancelSync != nil {
		s.cancelSync()
	}
	s.syncDone.Wait()
}

func (s *accountDataSyncer) syncLoop() {
	defer s.syncDone.Done()
	s.log.Debug().Msg("Starting account data sync loop")
	var ctx context.Context
	ctx, s.cancelSync = context.WithCancel(context.Background())

	syncer := &accountDataSyncHandler{
		parent:      s,
		isFirstSync: true,
	}
	s.client.Syncer = syncer
	s.client.SyncPresence = "offline"

	err := s.client.SyncWithContext(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		s.log.Err(err).Msg("Account data sync loop exited with error")
	} else {
		s.log.Debug().Msg("Account data sync loop stopped")
	}
}

type accountDataSyncHandler struct {
	parent      *accountDataSyncer
	isFirstSync bool
}

func (h *accountDataSyncHandler) ProcessResponse(ctx context.Context, resp *mautrix.RespSync, since string) error {
	if since == "" {
		// Skip the initial sync — it contains the full current state,
		// not changes we need to react to.
		h.isFirstSync = false
		return nil
	}
	if h.isFirstSync {
		h.isFirstSync = false
		return nil
	}

	for roomID, roomData := range resp.Rooms.Join {
		for _, evt := range roomData.AccountData.Events {
			h.handleAccountDataEvent(ctx, roomID, evt)
		}
	}
	return nil
}

func (h *accountDataSyncHandler) handleAccountDataEvent(ctx context.Context, roomID id.RoomID, evt *event.Event) {
	// Only handle known account data types
	isKnown := false
	for _, t := range accountDataTypes {
		if evt.Type.Type == t.Type {
			isKnown = true
			break
		}
	}
	if !isKnown {
		return
	}

	// Skip events that the bridge itself set (loop avoidance).
	// Compare raw content bytes to identify bridge echoes regardless of timing.
	if h.parent.wasRecentlySent(roomID, evt.Type.Type, evt.Content.VeryRaw) {
		h.parent.log.Debug().
			Stringer("room_id", roomID).
			Str("event_type", evt.Type.Type).
			Msg("Skipping account data event that was recently set by bridge")
		return
	}

	evt.RoomID = roomID
	evt.Sender = h.parent.userID
	evt.Type.Class = event.AccountDataEventType

	err := evt.Content.ParseRaw(evt.Type)
	if err != nil {
		h.parent.log.Warn().Err(err).
			Stringer("room_id", roomID).
			Str("event_type", evt.Type.Type).
			Msg("Failed to parse account data event content")
		return
	}

	h.parent.log.Debug().
		Stringer("room_id", roomID).
		Str("event_type", evt.Type.Type).
		Msg("Dispatching account data event from double puppet sync")
	h.parent.br.Bridge.QueueMatrixEvent(ctx, evt)
}

func (h *accountDataSyncHandler) OnFailedSync(_ *mautrix.RespSync, err error) (time.Duration, error) {
	if errors.Is(err, mautrix.MUnknownToken) {
		h.parent.log.Warn().Msg("Account data sync got M_UNKNOWN_TOKEN, stopping")
		return 0, err
	}
	h.parent.log.Err(err).Msg("Account data sync failed, retrying in 30 seconds")
	return 30 * time.Second, nil
}

func (h *accountDataSyncHandler) GetFilterJSON(_ id.UserID) *mautrix.Filter {
	everything := []event.Type{{Type: "*"}}
	return &mautrix.Filter{
		Presence:    &mautrix.FilterPart{NotTypes: everything},
		AccountData: &mautrix.FilterPart{NotTypes: everything},
		Room: &mautrix.RoomFilter{
			IncludeLeave: false,
			Ephemeral:    &mautrix.FilterPart{NotTypes: everything},
			AccountData:  &mautrix.FilterPart{Types: accountDataTypes},
			State:        &mautrix.FilterPart{NotTypes: everything},
			Timeline:     &mautrix.FilterPart{NotTypes: everything},
		},
	}
}
