// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"fmt"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
)

type MediaQuery struct {
	BridgeID networkid.BridgeID
	MetaType MetaTypeCreator
	*dbutil.QueryHelper[*Media]
}

type Media struct {
	BridgeID networkid.BridgeID
	ID       networkid.MediaID

	Metadata any
}

var _ driver.Value = (sqlMediaID)(nil)
var _ sql.Scanner = (sqlMediaID)(nil)

type sqlMediaID networkid.MediaID

func (id sqlMediaID) Scan(src any) (err error) {
	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("invalid sql type for media id: %T", v)
	}

	id, err = base64.RawStdEncoding.DecodeString(s)
	return
}

func (id sqlMediaID) Value() (driver.Value, error) {
	return base64.RawStdEncoding.EncodeToString(id), nil
}

const (
	getMediaQuery = `
		SELECT bridge_id, id, metadata FROM media
	`
	insertMediaQuery = `
		INSERT INTO media (
			bridge_id, id, metadata
		)
		VALUES ($1, $2, $3)
	`
	updateMediaQuery = `
		UPDATE media SET metadata=$3
		WHERE bridge_id=$1 AND id=$2
	`
	deleteMediaQuery = `
		DELETE FROM media WHERE bridge_id=$1 AND id=$2
	`
)

func (mq *MediaQuery) GetByID(ctx context.Context, mediaID networkid.MediaID) (*Media, error) {
	return mq.QueryOne(ctx, getMediaQuery, mq.BridgeID, sqlMediaID(mediaID))
}

func (mq *MediaQuery) Insert(ctx context.Context, media *Media) (err error) {
	ensureBridgeIDMatches(&media.BridgeID, mq.BridgeID)
	_, err = mq.GetDB().Exec(ctx, insertMediaQuery, media.ensureHasMetadata(mq.MetaType).sqlVariables()...)
	return
}

func (mq *MediaQuery) Update(ctx context.Context, media *Media) error {
	ensureBridgeIDMatches(&media.BridgeID, mq.BridgeID)
	return mq.Exec(ctx, updateMediaQuery, media.ensureHasMetadata(mq.MetaType).sqlVariables()...)
}

func (mq *MediaQuery) Delete(ctx context.Context, mediaID networkid.MediaID) error {
	return mq.Exec(ctx, deleteMediaQuery, mq.BridgeID, sqlMediaID(mediaID))
}

func (m *Media) Scan(row dbutil.Scannable) (*Media, error) {
	err := row.Scan(
		&m.BridgeID, (*sqlMediaID)(&m.ID), dbutil.JSON{Data: m.Metadata},
	)
	return m, err
}

func (m *Media) ensureHasMetadata(metaType MetaTypeCreator) *Media {
	if m.Metadata == nil {
		m.Metadata = metaType()
	}
	return m
}

func (m *Media) sqlVariables() []any {
	return []any{
		m.BridgeID, sqlMediaID(m.ID), dbutil.JSON{Data: m.Metadata},
	}
}
