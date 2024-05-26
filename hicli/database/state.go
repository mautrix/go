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
)

type CurrentStateQuery struct {
	*dbutil.Database
}

func (csq *CurrentStateQuery) Set(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, eventRowID int64, membership event.Membership) error {
	_, err := csq.Exec(ctx, setCurrentStateQuery, roomID, eventType.Type, stateKey, eventRowID, dbutil.StrPtr(membership))
	return err
}
