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

type BackfillQueueQuery struct {
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
		INSERT INTO backfill_queue (bridge_id, portal_id, portal_receiver, user_login_id, batch_count, is_done, next_dispatch_min_ts)
		VALUES ($1, $2, $3, $4, 0, false, $5)
		ON CONFLICT DO UPDATE
			SET user_login_id=excluded.user_login_id,
			    next_dispatch_min_ts=CASE
			        WHEN next_dispatch_min_ts=9223372036854775807
			            THEN excluded.next_dispatch_min_ts
			        ELSE next_dispatch_min_ts
				END
	`
	markBackfillDispatchedQuery = `
		UPDATE backfill_queue SET dispatched_at=$4, completed_at=NULL, next_dispatch_min_ts=$5
		WHERE bridge_id = $1 AND portal_id = $2 AND portal_receiver = $3
	`
	updateBackfillQueueQuery = `
		UPDATE backfill_queue
		SET user_login_id=$4, batch_count=$5, is_done=$6, cursor=$7, oldest_message_id=$8,
			dispatched_at=$9, completed_at=$10, next_dispatch_min_ts=$11
		WHERE bridge_id = $1 AND portal_id = $2 AND portal_receiver = $3
	`
	getNextBackfillQuery = `
		SELECT
			bridge_id, portal_id, portal_receiver, user_login_id, batch_count, is_done,
			cursor, oldest_message_id, dispatched_at, completed_at, next_dispatch_min_ts
		FROM backfill_queue
		WHERE bridge_id = $1 AND next_dispatch_min_ts < $2 AND is_done = false AND user_login_id <> ''
		ORDER BY next_dispatch_min_ts LIMIT 1
	`
	deleteBackfillQueueQuery = `
		DELETE FROM backfill_queue
		WHERE bridge_id = $1 AND portal_id = $2 AND portal_receiver = $3
	`
)

func (bqq *BackfillQueueQuery) EnsureExists(ctx context.Context, portal networkid.PortalKey) error {
	return bqq.Exec(ctx, ensureBackfillExistsQuery, bqq.BridgeID, portal.ID, portal.Receiver, time.Now().UnixNano())
}

const UnfinishedBackfillBackoff = 1 * time.Hour

func (bqq *BackfillQueueQuery) MarkDispatched(ctx context.Context, bq *BackfillTask) error {
	ensureBridgeIDMatches(&bq.BridgeID, bqq.BridgeID)
	bq.DispatchedAt = time.Now()
	bq.CompletedAt = time.Time{}
	bq.NextDispatchMinTS = bq.DispatchedAt.Add(UnfinishedBackfillBackoff)
	return bqq.Exec(
		ctx, markBackfillDispatchedQuery,
		bq.BridgeID, bq.PortalKey.ID, bq.PortalKey.Receiver,
		bq.DispatchedAt.UnixNano(), bq.NextDispatchMinTS.UnixNano(),
	)
}

func (bqq *BackfillQueueQuery) Update(ctx context.Context, bq *BackfillTask) error {
	ensureBridgeIDMatches(&bq.BridgeID, bqq.BridgeID)
	return bqq.Exec(ctx, updateBackfillQueueQuery, bq.sqlVariables()...)
}

func (bqq *BackfillQueueQuery) GetNext(ctx context.Context) (*BackfillTask, error) {
	return bqq.QueryOne(ctx, getNextBackfillQuery, bqq.BridgeID, time.Now().UnixNano())
}

func (bqq *BackfillQueueQuery) Delete(ctx context.Context, portalKey networkid.PortalKey) error {
	return bqq.Exec(ctx, deleteBackfillQueueQuery, bqq.BridgeID, portalKey.ID, portalKey.Receiver)
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
