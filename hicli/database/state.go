// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	setCurrentStateQuery = `
		INSERT INTO current_state (room_id, event_type, state_key, event_rowid, membership) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (room_id, event_type, state_key) DO UPDATE SET event_rowid = excluded.event_rowid, membership = excluded.membership
	`
	getCurrentRoomStateQuery = `
		SELECT event.rowid, -1, event.room_id, event.event_id, sender, event.type, event.state_key, timestamp, content, decrypted, decrypted_type, unsigned,
		       transaction_id, redacted_by, relates_to, relation_type, megolm_session_id, decryption_error, reactions, last_edit_rowid
		FROM current_state cs
		JOIN event ON cs.event_rowid = event.rowid
		WHERE cs.room_id = $1
	`
	getCurrentStateEventQuery = getCurrentRoomStateQuery + `AND cs.event_type = $2 AND cs.state_key = $3`
)

type CurrentStateQuery struct {
	*dbutil.QueryHelper[*Event]
}

func (csq *CurrentStateQuery) Set(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, eventRowID EventRowID, membership event.Membership) error {
	return csq.Exec(ctx, setCurrentStateQuery, roomID, eventType.Type, stateKey, eventRowID, dbutil.StrPtr(membership))
}

func (csq *CurrentStateQuery) Get(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string) (*Event, error) {
	return csq.QueryOne(ctx, getCurrentStateEventQuery, roomID, eventType.Type, stateKey)
}

func (csq *CurrentStateQuery) GetAll(ctx context.Context, roomID id.RoomID) ([]*Event, error) {
	return csq.QueryMany(ctx, getCurrentRoomStateQuery, roomID)
}
