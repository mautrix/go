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

	"maunium.net/go/mautrix/bridgev2/networkid"
)

type BackfillTaskQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.QueryHelper[*BackfillTask]
}

type BackfillTask struct {
	BridgeID    networkid.BridgeID
	PortalKey   networkid.PortalKey
	UserLoginID networkid.UserLoginID

	BatchCount        int
	IsDone            bool
	Cursor            networkid.PaginationCursor
	OldestMessageID   networkid.MessageID
	DispatchedAt      time.Time
	CompletedAt       time.Time
	NextDispatchMinTS time.Time
}

var BackfillNextDispatchNever = time.Unix(0, (1<<63)-1)

const (
	ensureBackfillExistsQuery = `
		INSERT INTO backfill_task (bridge_id, portal_id, portal_receiver, user_login_id, batch_count, is_done, next_dispatch_min_ts)
		VALUES ($1, $2, $3, $4, -1, false, $5)
		ON CONFLICT (bridge_id, portal_id, portal_receiver) DO UPDATE
			SET user_login_id=CASE
					WHEN backfill_task.user_login_id=''
						THEN excluded.user_login_id
					ELSE backfill_task.user_login_id
				END,
			    next_dispatch_min_ts=CASE
			        WHEN backfill_task.next_dispatch_min_ts=9223372036854775807
			            THEN excluded.next_dispatch_min_ts
			        ELSE backfill_task.next_dispatch_min_ts
				END
	`
	upsertBackfillQueueQuery = `
		INSERT INTO backfill_task (
			bridge_id, portal_id, portal_receiver, user_login_id, batch_count, is_done, cursor,
			oldest_message_id, dispatched_at, completed_at, next_dispatch_min_ts
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (bridge_id, portal_id, portal_receiver) DO UPDATE
			SET user_login_id=excluded.user_login_id,
				batch_count=excluded.batch_count,
				is_done=excluded.is_done,
				cursor=excluded.cursor,
				oldest_message_id=excluded.oldest_message_id,
				dispatched_at=excluded.dispatched_at,
				completed_at=excluded.completed_at,
				next_dispatch_min_ts=excluded.next_dispatch_min_ts
	`
	markBackfillDispatchedQuery = `
		UPDATE backfill_task SET dispatched_at=$4, completed_at=NULL, next_dispatch_min_ts=$5
		WHERE bridge_id = $1 AND portal_id = $2 AND portal_receiver = $3
	`
	updateBackfillQueueQuery = `
		UPDATE backfill_task
		SET user_login_id=$4, batch_count=$5, is_done=$6, cursor=$7, oldest_message_id=$8,
			dispatched_at=$9, completed_at=$10, next_dispatch_min_ts=$11
		WHERE bridge_id = $1 AND portal_id = $2 AND portal_receiver = $3
	`
	markBackfillTaskNotDoneQuery = `
		UPDATE backfill_task
		SET is_done = false
		WHERE bridge_id = $1 AND portal_id = $2 AND portal_receiver = $3 AND user_login_id = $4
	`
	getNextBackfillQuery = `
		SELECT
			bridge_id, portal_id, portal_receiver, user_login_id, batch_count, is_done,
			cursor, oldest_message_id, dispatched_at, completed_at, next_dispatch_min_ts
		FROM backfill_task
		WHERE bridge_id = $1 AND next_dispatch_min_ts < $2 AND is_done = false AND user_login_id <> ''
		ORDER BY next_dispatch_min_ts LIMIT 1
	`
	getNextBackfillQueryForPortal = `
		SELECT
			bridge_id, portal_id, portal_receiver, user_login_id, batch_count, is_done,
			cursor, oldest_message_id, dispatched_at, completed_at, next_dispatch_min_ts
		FROM backfill_task
		WHERE bridge_id = $1 AND portal_id = $2 AND portal_receiver = $3 AND is_done = false AND user_login_id <> ''
	`
	deleteBackfillQueueQuery = `
		DELETE FROM backfill_task
		WHERE bridge_id = $1 AND portal_id = $2 AND portal_receiver = $3
	`
)

func (btq *BackfillTaskQuery) EnsureExists(ctx context.Context, portal networkid.PortalKey, loginID networkid.UserLoginID) error {
	return btq.Exec(ctx, ensureBackfillExistsQuery, btq.BridgeID, portal.ID, portal.Receiver, loginID, time.Now().UnixNano())
}

func (btq *BackfillTaskQuery) Upsert(ctx context.Context, bq *BackfillTask) error {
	ensureBridgeIDMatches(&bq.BridgeID, btq.BridgeID)
	return btq.Exec(ctx, upsertBackfillQueueQuery, bq.sqlVariables()...)
}

const UnfinishedBackfillBackoff = 1 * time.Hour

func (btq *BackfillTaskQuery) MarkDispatched(ctx context.Context, bq *BackfillTask) error {
	ensureBridgeIDMatches(&bq.BridgeID, btq.BridgeID)
	bq.DispatchedAt = time.Now()
	bq.CompletedAt = time.Time{}
	bq.NextDispatchMinTS = bq.DispatchedAt.Add(UnfinishedBackfillBackoff)
	return btq.Exec(
		ctx, markBackfillDispatchedQuery,
		bq.BridgeID, bq.PortalKey.ID, bq.PortalKey.Receiver,
		bq.DispatchedAt.UnixNano(), bq.NextDispatchMinTS.UnixNano(),
	)
}

func (btq *BackfillTaskQuery) Update(ctx context.Context, bq *BackfillTask) error {
	ensureBridgeIDMatches(&bq.BridgeID, btq.BridgeID)
	return btq.Exec(ctx, updateBackfillQueueQuery, bq.sqlVariables()...)
}

func (btq *BackfillTaskQuery) MarkNotDone(ctx context.Context, portalKey networkid.PortalKey, userLoginID networkid.UserLoginID) error {
	return btq.Exec(ctx, markBackfillTaskNotDoneQuery, btq.BridgeID, portalKey.ID, portalKey.Receiver, userLoginID)
}

func (btq *BackfillTaskQuery) GetNext(ctx context.Context) (*BackfillTask, error) {
	return btq.QueryOne(ctx, getNextBackfillQuery, btq.BridgeID, time.Now().UnixNano())
}

func (btq *BackfillTaskQuery) GetNextForPortal(ctx context.Context, portalKey networkid.PortalKey) (*BackfillTask, error) {
	return btq.QueryOne(ctx, getNextBackfillQueryForPortal, btq.BridgeID, portalKey.ID, portalKey.Receiver)
}

func (btq *BackfillTaskQuery) Delete(ctx context.Context, portalKey networkid.PortalKey) error {
	return btq.Exec(ctx, deleteBackfillQueueQuery, btq.BridgeID, portalKey.ID, portalKey.Receiver)
}

func (bt *BackfillTask) Scan(row dbutil.Scannable) (*BackfillTask, error) {
	var cursor, oldestMessageID sql.NullString
	var dispatchedAt, completedAt, nextDispatchMinTS sql.NullInt64
	err := row.Scan(
		&bt.BridgeID, &bt.PortalKey.ID, &bt.PortalKey.Receiver, &bt.UserLoginID, &bt.BatchCount, &bt.IsDone,
		&cursor, &oldestMessageID, &dispatchedAt, &completedAt, &nextDispatchMinTS)
	if err != nil {
		return nil, err
	}
	bt.Cursor = networkid.PaginationCursor(cursor.String)
	bt.OldestMessageID = networkid.MessageID(oldestMessageID.String)
	if dispatchedAt.Valid {
		bt.DispatchedAt = time.Unix(0, dispatchedAt.Int64)
	}
	if completedAt.Valid {
		bt.CompletedAt = time.Unix(0, completedAt.Int64)
	}
	if nextDispatchMinTS.Valid {
		bt.NextDispatchMinTS = time.Unix(0, nextDispatchMinTS.Int64)
	}
	return bt, nil
}

func (bt *BackfillTask) sqlVariables() []any {
	return []any{
		bt.BridgeID, bt.PortalKey.ID, bt.PortalKey.Receiver, bt.UserLoginID, bt.BatchCount, bt.IsDone,
		dbutil.StrPtr(bt.Cursor), dbutil.StrPtr(bt.OldestMessageID),
		dbutil.ConvertedPtr(bt.DispatchedAt, time.Time.UnixNano),
		dbutil.ConvertedPtr(bt.CompletedAt, time.Time.UnixNano),
		bt.NextDispatchMinTS.UnixNano(),
	}
}
