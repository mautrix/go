// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sql_store_upgrade

import (
	"context"
	"embed"
	"fmt"

	"go.mau.fi/util/dbutil"
)

var Table dbutil.UpgradeTable

const VersionTableName = "crypto_version"

//go:embed *.sql
var fs embed.FS

func init() {
	Table.Register(-1, 3, 0, "Unsupported version", dbutil.TxnModeOff, func(ctx context.Context, database *dbutil.Database) error {
		return fmt.Errorf("upgrading from versions 1 and 2 of the crypto store is no longer supported in mautrix-go v0.12+")
	})
	Table.RegisterFS(fs)
}
