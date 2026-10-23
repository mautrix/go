// Copyright (c) 2026 Tulir Asokan
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

type EncryptedDirectMediaQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.QueryHelper[*EncryptedDirectMedia]
}

type EncryptedDirectMedia struct {
	BridgeID   networkid.BridgeID
	MediaID    string
	FLOEKey    string
	FLOEHeader string
	HandledAt  time.Time
}

const (
	insertEncryptedDirectMediaQuery = `
		INSERT INTO encrypted_direct_media (bridge_id, media_id, floe_key, floe_header, handled_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	markEncryptedDirectMediaHandledQuery = `
		UPDATE encrypted_direct_media SET handled_at=$3 WHERE bridge_id=$1 AND media_id=$2
	`
	getEncryptedDirectMediaQuery = `
		SELECT bridge_id, media_id, floe_key, floe_header, handled_at
		FROM encrypted_direct_media WHERE bridge_id=$1 AND media_id=$2
	`
)

func (edmq *EncryptedDirectMediaQuery) Put(ctx context.Context, dm *EncryptedDirectMedia) error {
	ensureBridgeIDMatches(&dm.BridgeID, edmq.BridgeID)
	return edmq.Exec(ctx, insertEncryptedDirectMediaQuery, dm.sqlVariables()...)
}

func (edmq *EncryptedDirectMediaQuery) MarkHandled(ctx context.Context, mediaID string) error {
	return edmq.Exec(ctx, markEncryptedDirectMediaHandledQuery, edmq.BridgeID, mediaID, time.Now().UnixNano())
}

func (edmq *EncryptedDirectMediaQuery) Get(ctx context.Context, mediaID string) (*EncryptedDirectMedia, error) {
	return edmq.QueryOne(ctx, getEncryptedDirectMediaQuery, edmq.BridgeID, mediaID)
}

func (edm *EncryptedDirectMedia) Scan(row dbutil.Scannable) (*EncryptedDirectMedia, error) {
	var handledAt sql.NullInt64
	var floeKey, floeHeader sql.NullString
	err := row.Scan(&edm.BridgeID, &edm.MediaID, &floeKey, &floeHeader, &handledAt)
	if err != nil {
		return nil, err
	}
	if handledAt.Int64 > 0 {
		edm.HandledAt = time.Unix(0, handledAt.Int64)
	}
	edm.FLOEKey = floeKey.String
	edm.FLOEHeader = floeHeader.String
	return edm, nil
}

func (edm *EncryptedDirectMedia) sqlVariables() []any {
	return []any{
		edm.BridgeID,
		edm.MediaID,
		dbutil.StrPtr(edm.FLOEKey),
		dbutil.StrPtr(edm.FLOEHeader),
		dbutil.ConvertedPtr(edm.HandledAt, time.Time.UnixNano),
	}
}
