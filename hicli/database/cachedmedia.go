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
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/id"
)

const (
	insertCachedMediaQuery = `
		INSERT INTO cached_media (mxc, event_rowid, enc_file, file_name, mime_type, size, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (mxc) DO NOTHING
	`
	upsertCachedMediaQuery = `
		INSERT INTO cached_media (mxc, event_rowid, enc_file, file_name, mime_type, size, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (mxc) DO UPDATE
			SET enc_file = excluded.enc_file,
			    file_name = excluded.file_name,
			    mime_type = excluded.mime_type,
			    size = excluded.size,
			    hash = excluded.hash
	`
	getCachedMediaQuery = `
		SELECT mxc, event_rowid, enc_file, file_name, mime_type, size, hash
		FROM cached_media
		WHERE mxc = $1
	`
)

type CachedMediaQuery struct {
	*dbutil.QueryHelper[*CachedMedia]
}

func (cmq *CachedMediaQuery) Add(ctx context.Context, cm *CachedMedia) error {
	return cmq.Exec(ctx, insertCachedMediaQuery, cm.sqlVariables()...)
}

func (cmq *CachedMediaQuery) Put(ctx context.Context, cm *CachedMedia) error {
	return cmq.Exec(ctx, upsertCachedMediaQuery, cm.sqlVariables()...)
}

func (cmq *CachedMediaQuery) Get(ctx context.Context, mxc id.ContentURI) (*CachedMedia, error) {
	return cmq.QueryOne(ctx, getCachedMediaQuery, &mxc)
}

type CachedMedia struct {
	MXC        id.ContentURI
	EventRowID EventRowID
	EncFile    *attachment.EncryptedFile
	FileName   string
	MimeType   string
	Size       int64
	Hash       *[32]byte
}

func (c *CachedMedia) sqlVariables() []any {
	var hash []byte
	if c.Hash != nil {
		hash = c.Hash[:]
	}
	return []any{
		&c.MXC, dbutil.NumPtr(c.EventRowID), dbutil.JSONPtr(c.EncFile),
		dbutil.StrPtr(c.FileName), dbutil.StrPtr(c.MimeType), dbutil.NumPtr(c.Size), hash,
	}
}

var safeMimes = []string{
	"text/css", "text/plain", "text/csv",
	"application/json", "application/ld+json",
	"image/jpeg", "image/gif", "image/png", "image/apng", "image/webp", "image/avif",
	"video/mp4", "video/webm", "video/ogg", "video/quicktime",
	"audio/mp4", "audio/webm", "audio/aac", "audio/mpeg", "audio/ogg", "audio/wave",
	"audio/wav", "audio/x-wav", "audio/x-pn-wav", "audio/flac", "audio/x-flac",
}

func (c *CachedMedia) Scan(row dbutil.Scannable) (*CachedMedia, error) {
	var mimeType, fileName sql.NullString
	var size, eventRowID sql.NullInt64
	var hash []byte
	err := row.Scan(&c.MXC, &eventRowID, dbutil.JSON{Data: &c.EncFile}, &fileName, &mimeType, &size, &hash)
	if err != nil {
		return nil, err
	}
	c.MimeType = mimeType.String
	c.FileName = fileName.String
	c.EventRowID = EventRowID(eventRowID.Int64)
	c.Size = size.Int64
	if hash != nil && len(hash) == 32 {
		c.Hash = (*[32]byte)(hash)
	}
	return c, nil
}

func (c *CachedMedia) ContentDisposition() string {
	if slices.Contains(safeMimes, c.MimeType) {
		return "inline"
	}
	return "attachment"
}
