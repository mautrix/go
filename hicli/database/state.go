// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"fmt"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exslices"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	setCurrentStateQuery = `
		INSERT INTO current_state (room_id, event_type, state_key, event_rowid, membership) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (room_id, event_type, state_key) DO UPDATE SET event_rowid = excluded.event_rowid, membership = excluded.membership
	`
	addCurrentStateQuery = `
		INSERT INTO current_state (room_id, event_type, state_key, event_rowid, membership) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING
	`
	deleteCurrentStateQuery = `
		DELETE FROM current_state WHERE room_id = $1
	`
	getCurrentRoomStateQuery = `
		SELECT event.rowid, -1, event.room_id, event.event_id, sender, event.type, event.state_key, timestamp, content, decrypted, decrypted_type, unsigned,
		       transaction_id, redacted_by, relates_to, relation_type, megolm_session_id, decryption_error, send_error, reactions, last_edit_rowid
		FROM current_state cs
		JOIN event ON cs.event_rowid = event.rowid
		WHERE cs.room_id = $1
	`
	getCurrentStateEventQuery = getCurrentRoomStateQuery + `AND cs.event_type = $2 AND cs.state_key = $3`
)

var massInsertCurrentStateBuilder = dbutil.NewMassInsertBuilder[*CurrentStateEntry, [1]any](addCurrentStateQuery, "($1, $%d, $%d, $%d, $%d)")

const currentStateMassInsertBatchSize = 1000

type CurrentStateEntry struct {
	EventType  event.Type
	StateKey   string
	EventRowID EventRowID
	Membership event.Membership
}

func (cse *CurrentStateEntry) GetMassInsertValues() [4]any {
	return [4]any{cse.EventType.Type, cse.StateKey, cse.EventRowID, dbutil.StrPtr(cse.Membership)}
}

type CurrentStateQuery struct {
	*dbutil.QueryHelper[*Event]
}

func (csq *CurrentStateQuery) Set(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, eventRowID EventRowID, membership event.Membership) error {
	return csq.Exec(ctx, setCurrentStateQuery, roomID, eventType.Type, stateKey, eventRowID, dbutil.StrPtr(membership))
}

func (csq *CurrentStateQuery) AddMany(ctx context.Context, roomID id.RoomID, deleteOld bool, entries []*CurrentStateEntry) error {
	var err error
	if deleteOld {
		err = csq.Exec(ctx, deleteCurrentStateQuery, roomID)
		if err != nil {
			return fmt.Errorf("failed to delete old state: %w", err)
		}
	}
	for _, entryChunk := range exslices.Chunk(entries, currentStateMassInsertBatchSize) {
		query, params := massInsertCurrentStateBuilder.Build([1]any{roomID}, entryChunk)
		err = csq.Exec(ctx, query, params...)
		if err != nil {
			return err
		}
	}
	return nil
}

func (csq *CurrentStateQuery) Add(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, eventRowID EventRowID, membership event.Membership) error {
	return csq.Exec(ctx, addCurrentStateQuery, roomID, eventType.Type, stateKey, eventRowID, dbutil.StrPtr(membership))
}

func (csq *CurrentStateQuery) Get(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string) (*Event, error) {
	return csq.QueryOne(ctx, getCurrentStateEventQuery, roomID, eventType.Type, stateKey)
}

func (csq *CurrentStateQuery) GetAll(ctx context.Context, roomID id.RoomID) ([]*Event, error) {
	return csq.QueryMany(ctx, getCurrentRoomStateQuery, roomID)
}
