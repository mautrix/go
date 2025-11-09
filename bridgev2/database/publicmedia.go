// Copyright (c) 2025 Tulir Asokan
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
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/id"
)

type PublicMediaQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.QueryHelper[*PublicMedia]
}

type PublicMedia struct {
	BridgeID networkid.BridgeID
	PublicID string
	MXC      id.ContentURI
	Keys     *attachment.EncryptedFile
	MimeType string
	Expiry   time.Time
}

const (
	upsertPublicMediaQuery = `
		INSERT INTO public_media (bridge_id, public_id, mxc, keys, mimetype, expiry)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (bridge_id, public_id) DO UPDATE SET expiry=EXCLUDED.expiry
	`
	getPublicMediaQuery = `
		SELECT bridge_id, public_id, mxc, keys, mimetype, expiry
		FROM public_media WHERE bridge_id=$1 AND public_id=$2
	`
)

func (pmq *PublicMediaQuery) Put(ctx context.Context, pm *PublicMedia) error {
	ensureBridgeIDMatches(&pm.BridgeID, pmq.BridgeID)
	return pmq.Exec(ctx, upsertPublicMediaQuery, pm.sqlVariables()...)
}

func (pmq *PublicMediaQuery) Get(ctx context.Context, publicID string) (*PublicMedia, error) {
	return pmq.QueryOne(ctx, getPublicMediaQuery, pmq.BridgeID, publicID)
}

func (pm *PublicMedia) Scan(row dbutil.Scannable) (*PublicMedia, error) {
	var expiry sql.NullInt64
	var mimetype sql.NullString
	err := row.Scan(&pm.BridgeID, &pm.PublicID, &pm.MXC, dbutil.JSON{Data: &pm.Keys}, &mimetype, &expiry)
	if err != nil {
		return nil, err
	}
	if expiry.Valid {
		pm.Expiry = time.Unix(0, expiry.Int64)
	}
	pm.MimeType = mimetype.String
	return pm, nil
}

func (pm *PublicMedia) sqlVariables() []any {
	return []any{pm.BridgeID, pm.PublicID, &pm.MXC, dbutil.JSONPtr(pm.Keys), dbutil.StrPtr(pm.MimeType), dbutil.ConvertedPtr(pm.Expiry, time.Time.UnixNano)}
}
