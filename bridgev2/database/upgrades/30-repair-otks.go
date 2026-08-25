// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build go1.27 || goexperiment.jsonv2

package upgrades

import (
	"context"

	"go.mau.fi/util/dbutil"
)

var upgradeV30 = dbutil.WrapUpgrade(-1, 30, 9, "Mark OTKs as needing repair", dbutil.TxnModeOn, func(ctx context.Context, db *dbutil.Database) error {
	exists, err := db.TableExists(ctx, "crypto_account")
	if err != nil || !exists {
		return err
	}
	_, err = db.Exec(ctx, `
		INSERT INTO kv_store (bridge_id, key, value) VALUES ('', 'otk_repair_needed', 'true')
		ON CONFLICT (bridge_id, key) DO UPDATE SET value = 'true'
	`)
	return err
})
