// Copyright (c) 2026 Killian Lelong
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"fmt"
	"time"

	"maunium.net/go/mautrix/id"
)

type ViewLimitedMessage struct {
	Limit   string
	Hash    string
	Request string
	State   string
}

func (db *Database) PutViewLimited(ctx context.Context, mxid id.EventID, limit, hash string) error {
	res, err := db.Exec(ctx, `INSERT INTO view_limited_message (bridge_id, mxid, limit_json, content_hash) VALUES ($1, $2, $3, $4)
		ON CONFLICT (bridge_id, mxid) DO UPDATE SET
		limit_json=excluded.limit_json,
		content_hash=excluded.content_hash
		WHERE view_limited_message.state='ready' AND view_limited_message.viewed_at=0`, db.BridgeID, mxid, limit, hash)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 0 {
		return err
	}
	_, err = db.Exec(ctx, `UPDATE view_limited_message SET limit_json='{}', content_hash='', request='', state='done', type='view_limited', disappear_at=$4
		WHERE bridge_id=$1 AND mxid=$2 AND state IN ('ready', 'pending', 'apply') AND content_hash<>$3`, db.BridgeID, mxid, hash, time.Now().UnixNano())
	return err
}

func (db *Database) GetViewLimited(ctx context.Context, mxid id.EventID) (*ViewLimitedMessage, error) {
	var msg ViewLimitedMessage
	err := db.QueryRow(ctx, `SELECT limit_json, content_hash, request, state FROM view_limited_message WHERE bridge_id=$1 AND mxid=$2`, db.BridgeID, mxid).
		Scan(&msg.Limit, &msg.Hash, &msg.Request, &msg.State)
	return &msg, err
}

func (db *Database) ClaimViewLimited(ctx context.Context, mxid id.EventID, hash, request string, viewedAt time.Time) (bool, error) {
	res, err := db.Exec(ctx, `UPDATE view_limited_message SET request=$4, state='pending', viewed_at=$5, type='view_limited_pending', disappear_at=$6
		WHERE bridge_id=$1 AND mxid=$2 AND content_hash=$3 AND limit_json=$4 AND state='ready'
		AND (disappear_at IS NULL OR disappear_at>$5)
		AND NOT EXISTS (SELECT 1 FROM disappearing_message WHERE bridge_id=$1 AND mxid=$2 AND disappear_at<=$5)`, db.BridgeID, mxid, hash, request, viewedAt.UnixNano(), viewedAt.Add(time.Minute).UnixNano())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (db *Database) ExpireViewLimited(ctx context.Context, mxid id.EventID, deadline, viewedAt time.Time, pendingOnly bool) (bool, error) {
	res, err := db.Exec(ctx, `UPDATE view_limited_message SET limit_json='{}', content_hash='', request='', state='done' WHERE bridge_id=$1 AND mxid=$2 AND (NOT $4 OR state IN ('pending', 'apply'))
		AND viewed_at=$5 AND disappear_at=$3`, db.BridgeID, mxid, deadline.UnixNano(), pendingOnly, viewedAt.UnixNano())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (db *Database) UpdateViewLimited(ctx context.Context, mxid id.EventID, limit, hash, state string) error {
	res, err := db.Exec(ctx, `UPDATE view_limited_message SET limit_json=$3, content_hash=$4, request=CASE WHEN $5 IN ('ready', 'done') THEN '' ELSE request END, state=$5,
		disappear_at=CASE WHEN $5='ready' THEN NULL ELSE disappear_at END WHERE bridge_id=$1 AND mxid=$2
		AND (($5='apply' AND state='pending') OR ($5='ready' AND state='apply' AND content_hash=$4 AND limit_json=$3) OR ($5='done' AND state='pending'))`, db.BridgeID, mxid, limit, hash, state)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return fmt.Errorf("media already expired")
	}
	return err
}
