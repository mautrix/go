// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sql_store_upgrade

import (
	"context"

	"go.mau.fi/util/dbutil"
)

var DropCryptoMessageIndexForRewrite = false

func init() {
	const rewritePostgres = `
		ALTER TABLE crypto_message_index DROP CONSTRAINT crypto_message_index_pkey;
		ALTER TABLE crypto_message_index DROP COLUMN sender_key;
		ALTER TABLE crypto_message_index ADD PRIMARY KEY (session_id, "index");
	`
	const createNewSQLite = `
		CREATE TABLE new_crypto_message_index (
			session_id CHAR(43),
			"index"    INTEGER,
			event_id   TEXT   NOT NULL,
			timestamp  BIGINT NOT NULL,
			PRIMARY KEY (session_id, "index")
		);
	`
	const migrateSQLite = `
		INSERT INTO new_crypto_message_index (session_id, "index", event_id, timestamp)
		SELECT session_id, "index", event_id, timestamp FROM crypto_message_index;
	`
	const dropSQLite = `
		DROP TABLE crypto_message_index;
		ALTER TABLE new_crypto_message_index RENAME TO crypto_message_index;
	`
	Table.Register(-1, 20, 20, "Remove sender_key from crypto_message_index", dbutil.TxnModeOn, func(ctx context.Context, db *dbutil.Database) (err error) {
		switch db.Dialect {
		case dbutil.Postgres:
			_, err = db.Exec(ctx, rewritePostgres)
		case dbutil.SQLite:
			if DropCryptoMessageIndexForRewrite {
				_, err = db.Exec(ctx, createNewSQLite+dropSQLite)
			} else {
				_, err = db.Exec(ctx, createNewSQLite+migrateSQLite+dropSQLite)
			}
		default:
			err = dbutil.ErrUnsupportedDialect
		}
		return
	})
}
