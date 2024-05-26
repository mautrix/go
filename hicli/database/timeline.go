// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/id"
)

const (
	clearTimelineQuery = `
		DELETE FROM timeline WHERE room_id = $1
	`
	setTimelineQuery = `
		INSERT INTO timeline (room_id, event_rowid) VALUES ($1, $2)
	`
)

type MassInsertableRowID int64

func (m MassInsertableRowID) GetMassInsertValues() [1]any {
	return [1]any{m}
}

var setTimelineQueryBuilder = dbutil.NewMassInsertBuilder[MassInsertableRowID, [1]any](setTimelineQuery, "($1, $%d)")

type TimelineQuery struct {
	*dbutil.Database
}

func (tq *TimelineQuery) Clear(ctx context.Context, roomID id.RoomID) error {
	_, err := tq.Exec(ctx, clearTimelineQuery, roomID)
	return err
}

func (tq *TimelineQuery) Append(ctx context.Context, roomID id.RoomID, rowIDs []MassInsertableRowID) error {
	query, params := setTimelineQueryBuilder.Build([1]any{roomID}, rowIDs)
	_, err := tq.Exec(ctx, query, params...)
	return err
}
