// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mxmain

import (
	"context"
	"database/sql"
	"errors"
)

func (br *BridgeMain) LegacyMigrateSimple(renameTablesQuery, copyDataQuery string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		_, err := br.DB.Exec(ctx, renameTablesQuery)
		if err != nil {
			return err
		}
		upgradesTo, compat, err := br.DB.UpgradeTable[0].DangerouslyRun(ctx, br.DB)
		if err != nil {
			return err
		}
		_, err = br.DB.Exec(ctx, copyDataQuery)
		if err != nil {
			return err
		}
		_, err = br.DB.Exec(ctx, "UPDATE database_owner SET owner = $1 WHERE key = 0", br.DB.Owner)
		if err != nil {
			return err
		}
		_, err = br.DB.Exec(ctx, "UPDATE version SET version = $1, compat = $2", upgradesTo, compat)
		if err != nil {
			return err
		}

		return nil
	}
}

func (br *BridgeMain) CheckLegacyDB(expectedVersion int, minBridgeVersion, firstMegaVersion string, migrator func(context.Context) error, transaction bool) {
	log := br.Log.With().Str("action", "migrate legacy db").Logger()
	ctx := log.WithContext(context.Background())
	exists, err := br.DB.TableExists(ctx, "database_owner")
	if err != nil {
		log.Err(err).Msg("Failed to check if database_owner table exists")
		return
	} else if !exists {
		return
	}
	var owner string
	err = br.DB.QueryRow(ctx, "SELECT owner FROM database_owner WHERE key=0").Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Err(err).Msg("Failed to get database owner")
		return
	} else if owner != br.Name {
		if owner != "megabridge/"+br.Name && owner != "" {
			log.Warn().Str("db_owner", owner).Msg("Unexpected database owner, not migrating database")
		}
		return
	}
	var dbVersion int
	err = br.DB.QueryRow(ctx, "SELECT version FROM version").Scan(&dbVersion)
	if dbVersion < expectedVersion {
		log.Fatal().
			Int("expected_version", expectedVersion).
			Int("version", dbVersion).
			Msgf("Unsupported database version. Please upgrade to %s %s or higher before upgrading to %s.", br.Name, minBridgeVersion, firstMegaVersion) // zerolog-allow-msgf
		return
	} else if dbVersion > expectedVersion {
		log.Fatal().
			Int("expected_version", expectedVersion).
			Int("version", dbVersion).
			Msg("Unsupported database version (higher than expected)")
		return
	}
	log.Info().Msg("Detected legacy database, migrating...")
	if transaction {
		err = br.DB.DoTxn(ctx, nil, migrator)
	} else {
		err = migrator(ctx)
	}
	if err != nil {
		br.LogDBUpgradeErrorAndExit("main", err, "Failed to migrate legacy database")
	} else {
		log.Info().Msg("Successfully migrated legacy database")
	}
}
