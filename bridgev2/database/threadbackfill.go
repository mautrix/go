// Copyright (c) 2026 Automattic Inc.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"time"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
)

type ThreadBackfillTaskQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.QueryHelper[*ThreadBackfillTask]
}

type ThreadBackfillTask struct {
	BridgeID          networkid.BridgeID
	PortalKey         networkid.PortalKey
	ThreadRootID      networkid.MessageID
	UserLoginID       networkid.UserLoginID
	NextDispatchMinTS time.Time
}

const (
	insertThreadBackfillTaskQuery = `
		INSERT INTO thread_backfill_task (bridge_id, portal_id, portal_receiver, thread_root_id, user_login_id, next_dispatch_min_ts)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (bridge_id, portal_id, portal_receiver, thread_root_id) DO NOTHING
	`
	getNextThreadBackfillTaskQuery = `
		SELECT bridge_id, portal_id, portal_receiver, thread_root_id, user_login_id, next_dispatch_min_ts
		FROM thread_backfill_task
		WHERE bridge_id=$1 AND next_dispatch_min_ts<$2
		ORDER BY next_dispatch_min_ts LIMIT 1
	`
	postponeThreadBackfillTaskQuery = `
		UPDATE thread_backfill_task SET next_dispatch_min_ts=$5
		WHERE bridge_id=$1 AND portal_id=$2 AND portal_receiver=$3 AND thread_root_id=$4
	`
	deleteThreadBackfillTaskQuery = `
		DELETE FROM thread_backfill_task WHERE bridge_id=$1 AND portal_id=$2 AND portal_receiver=$3 AND thread_root_id=$4
	`
)

func (tbtq *ThreadBackfillTaskQuery) Insert(ctx context.Context, task *ThreadBackfillTask) error {
	ensureBridgeIDMatches(&task.BridgeID, tbtq.BridgeID)
	return tbtq.Exec(ctx, insertThreadBackfillTaskQuery, task.sqlVariables()...)
}

func (tbtq *ThreadBackfillTaskQuery) GetNext(ctx context.Context) (*ThreadBackfillTask, error) {
	return tbtq.QueryOne(ctx, getNextThreadBackfillTaskQuery, tbtq.BridgeID, time.Now().UnixNano())
}

func (tbtq *ThreadBackfillTaskQuery) Postpone(ctx context.Context, task *ThreadBackfillTask, until time.Time) error {
	ensureBridgeIDMatches(&task.BridgeID, tbtq.BridgeID)
	task.NextDispatchMinTS = until
	return tbtq.Exec(ctx, postponeThreadBackfillTaskQuery, task.BridgeID, task.PortalKey.ID, task.PortalKey.Receiver, task.ThreadRootID, until.UnixNano())
}

func (tbtq *ThreadBackfillTaskQuery) Delete(ctx context.Context, task *ThreadBackfillTask) error {
	ensureBridgeIDMatches(&task.BridgeID, tbtq.BridgeID)
	return tbtq.Exec(ctx, deleteThreadBackfillTaskQuery, task.BridgeID, task.PortalKey.ID, task.PortalKey.Receiver, task.ThreadRootID)
}

func (tbt *ThreadBackfillTask) Scan(row dbutil.Scannable) (*ThreadBackfillTask, error) {
	var nextDispatchMinTS int64
	err := row.Scan(&tbt.BridgeID, &tbt.PortalKey.ID, &tbt.PortalKey.Receiver, &tbt.ThreadRootID, &tbt.UserLoginID, &nextDispatchMinTS)
	if err != nil {
		return nil, err
	}
	tbt.NextDispatchMinTS = time.Unix(0, nextDispatchMinTS)
	return tbt, nil
}

func (tbt *ThreadBackfillTask) sqlVariables() []any {
	return []any{
		tbt.BridgeID,
		tbt.PortalKey.ID,
		tbt.PortalKey.Receiver,
		tbt.ThreadRootID,
		tbt.UserLoginID,
		tbt.NextDispatchMinTS.UnixNano(),
	}
}
