// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"database/sql"
	"errors"
	"sync"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/id"
)

const (
	clearTimelineQuery = `
		DELETE FROM timeline WHERE room_id = $1
	`
	appendTimelineQuery = `
		INSERT INTO timeline (room_id, event_rowid) VALUES ($1, $2)
	`
	prependTimelineQuery = `
		INSERT INTO timeline (room_id, rowid, event_rowid) VALUES ($1, $2, $3)
	`
	findMinRowIDQuery = `SELECT MIN(rowid) FROM timeline`
)

type TimelineRowID int64

type TimelinePrepend struct {
	Timeline TimelineRowID
	Event    EventRowID
}

func (tp TimelinePrepend) GetMassInsertValues() [2]any {
	return [2]any{tp.Timeline, tp.Event}
}

var appendTimelineQueryBuilder = dbutil.NewMassInsertBuilder[EventRowID, [1]any](appendTimelineQuery, "($1, $%d)")
var prependTimelineQueryBuilder = dbutil.NewMassInsertBuilder[TimelinePrepend, [1]any](prependTimelineQuery, "($1, $%d, $%d)")

type TimelineQuery struct {
	*dbutil.Database

	minRowID      TimelineRowID
	minRowIDFound bool
	prependLock   sync.Mutex
}

// Clear clears the timeline of a given room.
func (tq *TimelineQuery) Clear(ctx context.Context, roomID id.RoomID) error {
	_, err := tq.Exec(ctx, clearTimelineQuery, roomID)
	return err
}

func (tq *TimelineQuery) reserveRowIDs(ctx context.Context, count int) (startFrom TimelineRowID, err error) {
	tq.prependLock.Lock()
	defer tq.prependLock.Unlock()
	if !tq.minRowIDFound {
		err = tq.QueryRow(ctx, findMinRowIDQuery).Scan(&tq.minRowID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return
		}
		if tq.minRowID >= 0 {
			// No negative row IDs exist, start at -1
			tq.minRowID = -1
		} else {
			// We fetched the lowest row ID, but we want the next available one, so decrement one
			tq.minRowID--
		}
	}
	startFrom = tq.minRowID
	tq.minRowID -= TimelineRowID(count)
	return
}

// Prepend adds the given event row IDs to the beginning of the timeline.
// The events must be sorted in reverse chronological order (newest event first).
func (tq *TimelineQuery) Prepend(ctx context.Context, roomID id.RoomID, rowIDs []EventRowID) error {
	startFrom, err := tq.reserveRowIDs(ctx, len(rowIDs))
	if err != nil {
		return err
	}
	prependEntries := make([]TimelinePrepend, len(rowIDs))
	for i, rowID := range rowIDs {
		prependEntries[i] = TimelinePrepend{
			Timeline: startFrom - TimelineRowID(i),
			Event:    rowID,
		}
	}
	query, params := prependTimelineQueryBuilder.Build([1]any{roomID}, prependEntries)
	_, err = tq.Exec(ctx, query, params...)
	return err
}

// Append adds the given event row IDs to the end of the timeline.
func (tq *TimelineQuery) Append(ctx context.Context, roomID id.RoomID, rowIDs []EventRowID) error {
	query, params := appendTimelineQueryBuilder.Build([1]any{roomID}, rowIDs)
	_, err := tq.Exec(ctx, query, params...)
	return err
}
