// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"database/sql"
	"time"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	getRoomBaseQuery = `
		SELECT room_id, creation_content, name, avatar, topic, lazy_load_summary, encryption_event, has_member_list,
		       preview_event_rowid, sorting_timestamp, prev_batch
		FROM room
	`
	getRoomByIDQuery      = getRoomBaseQuery + `WHERE room_id = $1`
	ensureRoomExistsQuery = `
		INSERT INTO room (room_id) VALUES ($1)
		ON CONFLICT (room_id) DO NOTHING
	`
	upsertRoomFromSyncQuery = `
		UPDATE room
		SET creation_content = COALESCE(room.creation_content, $2),
			name = COALESCE($3, room.name),
			avatar = COALESCE($4, room.avatar),
			topic = COALESCE($5, room.topic),
			lazy_load_summary = COALESCE($6, room.lazy_load_summary),
			encryption_event = COALESCE($7, room.encryption_event),
			has_member_list = room.has_member_list OR $8,
			preview_event_rowid = COALESCE($9, room.preview_event_rowid),
			sorting_timestamp = COALESCE($10, room.sorting_timestamp),
			prev_batch = COALESCE($11, room.prev_batch)
		WHERE room_id = $1
	`
	setRoomPrevBatchQuery = `
		UPDATE room SET prev_batch = $2 WHERE room_id = $1
	`
	updateRoomPreviewIfLaterOnTimelineQuery = `
		UPDATE room
		SET preview_event_rowid = $2
		WHERE room_id = $1
		  AND COALESCE((SELECT rowid FROM timeline WHERE event_rowid = $2), -1)
		          > COALESCE((SELECT rowid FROM timeline WHERE event_rowid = preview_event_rowid), 0)
	`
)

type RoomQuery struct {
	*dbutil.QueryHelper[*Room]
}

func (rq *RoomQuery) Get(ctx context.Context, roomID id.RoomID) (*Room, error) {
	return rq.QueryOne(ctx, getRoomByIDQuery, roomID)
}

func (rq *RoomQuery) Upsert(ctx context.Context, room *Room) error {
	return rq.Exec(ctx, upsertRoomFromSyncQuery, room.sqlVariables()...)
}

func (rq *RoomQuery) CreateRow(ctx context.Context, roomID id.RoomID) error {
	return rq.Exec(ctx, ensureRoomExistsQuery, roomID)
}

func (rq *RoomQuery) SetPrevBatch(ctx context.Context, roomID id.RoomID, prevBatch string) error {
	return rq.Exec(ctx, setRoomPrevBatchQuery, roomID, prevBatch)
}

func (rq *RoomQuery) UpdatePreviewIfLaterOnTimeline(ctx context.Context, roomID id.RoomID, rowID EventRowID) error {
	return rq.Exec(ctx, updateRoomPreviewIfLaterOnTimelineQuery, roomID, rowID)
}

type Room struct {
	ID              id.RoomID
	CreationContent *event.CreateEventContent

	Name   *string
	Avatar *id.ContentURI
	Topic  *string

	LazyLoadSummary *mautrix.LazyLoadSummary

	EncryptionEvent *event.EncryptionEventContent
	HasMemberList   bool

	PreviewEventRowID EventRowID
	SortingTimestamp  time.Time

	PrevBatch string
}

func (r *Room) Scan(row dbutil.Scannable) (*Room, error) {
	var prevBatch sql.NullString
	var previewEventRowID, sortingTimestamp sql.NullInt64
	err := row.Scan(
		&r.ID,
		dbutil.JSON{Data: &r.CreationContent},
		&r.Name,
		&r.Avatar,
		&r.Topic,
		dbutil.JSON{Data: &r.LazyLoadSummary},
		dbutil.JSON{Data: &r.EncryptionEvent},
		&r.HasMemberList,
		&previewEventRowID,
		&sortingTimestamp,
		&prevBatch,
	)
	if err != nil {
		return nil, err
	}
	r.PrevBatch = prevBatch.String
	r.PreviewEventRowID = EventRowID(previewEventRowID.Int64)
	r.SortingTimestamp = time.UnixMilli(sortingTimestamp.Int64)
	return r, nil
}

func (r *Room) sqlVariables() []any {
	return []any{
		r.ID,
		dbutil.JSONPtr(r.CreationContent),
		r.Name,
		r.Avatar,
		r.Topic,
		dbutil.JSONPtr(r.LazyLoadSummary),
		dbutil.JSONPtr(r.EncryptionEvent),
		r.HasMemberList,
		dbutil.NumPtr(r.PreviewEventRowID),
		dbutil.UnixMilliPtr(r.SortingTimestamp),
		dbutil.StrPtr(r.PrevBatch),
	}
}

func (r *Room) BumpSortingTimestamp(evt *Event) bool {
	if !evt.BumpsSortingTimestamp() || evt.Timestamp.Before(r.SortingTimestamp) {
		return false
	}
	r.SortingTimestamp = evt.Timestamp
	now := time.Now()
	if r.SortingTimestamp.After(now) {
		r.SortingTimestamp = now
	}
	return true
}
