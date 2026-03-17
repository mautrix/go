// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
)

type Key string

const (
	KeySplitPortalsEnabled     Key = "split_portals_enabled"
	KeyBridgeInfoVersion       Key = "bridge_info_version"
	KeyEncryptionStateResynced Key = "encryption_state_resynced"
	KeyRecoveryKey             Key = "recovery_key"
)

type KVQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.Database
}

const (
	getKVQuery = `SELECT value FROM kv_store WHERE bridge_id = $1 AND key = $2`
	setKVQuery = `
		INSERT INTO kv_store (bridge_id, key, value) VALUES ($1, $2, $3)
		ON CONFLICT (bridge_id, key) DO UPDATE SET value = $3
	`
)

func (kvq *KVQuery) Get(ctx context.Context, key Key) string {
	var value string
	err := kvq.QueryRow(ctx, getKVQuery, kvq.BridgeID, key).Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		zerolog.Ctx(ctx).Err(err).Str("key", string(key)).Msg("Failed to get key from kvstore")
	}
	return value
}

func (kvq *KVQuery) Set(ctx context.Context, key Key, value string) {
	_, err := kvq.Exec(ctx, setKVQuery, kvq.BridgeID, key, value)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Str("key", string(key)).
			Str("value", value).
			Msg("Failed to set key in kvstore")
	}
}
