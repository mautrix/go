// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"errors"
	"os"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (br *Connector) configureRelaySyncer() {
	everything := []event.Type{{Type: "*"}}
	syncer := mautrix.NewDefaultSyncer()
	syncer.FilterJSON = &mautrix.Filter{
		Presence:    &mautrix.FilterPart{NotTypes: everything},
		AccountData: &mautrix.FilterPart{NotTypes: everything},
		Room: &mautrix.RoomFilter{
			IncludeLeave: false,
			AccountData:  &mautrix.FilterPart{NotTypes: everything},
			State:        &mautrix.FilterPart{LazyLoadMembers: true},
		},
	}
	syncer.ParseEventContent = true
	syncer.OnSync(br.Bot.MoveInviteState)
	syncer.OnSync(br.Bot.DontProcessOldEvents)
	syncer.OnSync(br.Crypto.ProcessSyncResponse)
	syncer.OnEvent(func(ctx context.Context, evt *event.Event) {
		src := evt.Mautrix.EventSource
		if src&(event.SourceState|event.SourceTimeline|event.SourceEphemeral) != 0 {
			br.EventProcessor.Dispatch(ctx, evt)
		}
	})
	br.Bot.Syncer = syncer
	br.Bot.Store = &RelaySyncStore{c: br}
}

func (br *Connector) startRelaySyncer() {
	var ctx context.Context
	ctx, br.stopBotSync = context.WithCancel(context.Background())
	ctx = br.Log.WithContext(ctx)
	br.botSyncDone.Add(1)
	defer br.botSyncDone.Done()
	err := br.Bot.SyncWithContext(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		br.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Fatal error syncing")
		os.Exit(51)
	}
	br.Log.Info().Msg("Bridge bot syncer stopped without error")
}

func (br *Connector) stopRelaySyncer() {
	if fn := br.stopBotSync; fn != nil {
		fn()
		br.botSyncDone.Wait()
	}
}

type RelaySyncStore struct {
	c *Connector
}

var _ mautrix.SyncStore = (*RelaySyncStore)(nil)

func (r *RelaySyncStore) SaveFilterID(ctx context.Context, userID id.UserID, filterID string) error {
	return nil
}

func (r *RelaySyncStore) LoadFilterID(ctx context.Context, userID id.UserID) (string, error) {
	return "", nil
}

func makeSyncTokenKey(userID id.UserID) database.Key {
	return database.Key("synctoken_" + userID.String())
}

func (r *RelaySyncStore) SaveNextBatch(ctx context.Context, userID id.UserID, nextBatchToken string) error {
	r.c.Bridge.DB.KV.Set(ctx, makeSyncTokenKey(userID), nextBatchToken)
	return nil
}

func (r *RelaySyncStore) LoadNextBatch(ctx context.Context, userID id.UserID) (string, error) {
	return r.c.Bridge.DB.KV.Get(ctx, makeSyncTokenKey(userID)), nil
}
