// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"database/sql"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	getRoomByIDQuery = `
		SELECT room_id, creation_content, name, avatar, topic, lazy_load_summary, encryption_event, has_member_list, prev_batch
		FROM room WHERE room_id = $1
	`
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
			prev_batch = COALESCE(room.prev_batch, $9)
		WHERE room_id = $1
	`
	setRoomPrevBatchQuery = `
		INSERT INTO room (room_id, prev_batch) VALUES ($1, $2)
		ON CONFLICT (room_id) DO UPDATE SET prev_batch = excluded.prev_batch
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

type Room struct {
	ID              id.RoomID
	CreationContent *event.CreateEventContent

	Name   *string
	Avatar *id.ContentURI
	Topic  *string

	LazyLoadSummary *mautrix.LazyLoadSummary

	EncryptionEvent *event.EncryptionEventContent
	HasMemberList   bool

	PrevBatch string
}

func (r *Room) Scan(row dbutil.Scannable) (*Room, error) {
	var prevBatch sql.NullString
	err := row.Scan(
		&r.ID,
		dbutil.JSON{Data: &r.CreationContent},
		&r.Name,
		&r.Avatar,
		&r.Topic,
		dbutil.JSON{Data: &r.LazyLoadSummary},
		dbutil.JSON{Data: &r.EncryptionEvent},
		&r.HasMemberList,
		&prevBatch,
	)
	if err != nil {
		return nil, err
	}
	r.PrevBatch = prevBatch.String
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
		dbutil.StrPtr(r.PrevBatch),
	}
}
