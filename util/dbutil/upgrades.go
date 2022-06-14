// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dbutil

import (
	"database/sql"
	"errors"
	"fmt"

	log "maunium.net/go/maulogger/v2"
)

type upgradeFunc func(*sql.Tx, *Database) error

type upgrade struct {
	message string
	fn      upgradeFunc

	upgradesTo int
}

type Upgrader struct {
	*sql.DB
	Log     log.Logger
	Dialect Dialect
}

var ErrUnsupportedDatabaseVersion = fmt.Errorf("unsupported database schema version")
var ErrForeignTables = fmt.Errorf("the database contains foreign tables")
var ErrNotOwned = fmt.Errorf("the database is owned by")

func (db *Database) getVersion() (int, error) {
	_, err := db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (version INTEGER)", db.VersionTable))
	if err != nil {
		return -1, err
	}

	version := 0
	err = db.QueryRow(fmt.Sprintf("SELECT version FROM %s LIMIT 1", db.VersionTable)).Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return -1, err
	}
	return version, nil
}

const tableExistsPostgres = "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name=$1)"
const tableExistsSQLite = "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND table_name=$1)"

func (db *Database) tableExists(table string) (exists bool) {
	if db.Dialect == SQLite {
		_ = db.QueryRow(tableExistsSQLite, table).Scan(&exists)
	} else if db.Dialect == Postgres {
		_ = db.QueryRow(tableExistsPostgres, table).Scan(&exists)
	}
	return
}

const createOwnerTable = `
CREATE TABLE IF NOT EXISTS database_owner (
	key   INTEGER PRIMARY KEY DEFAULT 0,
	owner TEXT NOT NULL
)
`

func (db *Database) checkDatabaseOwner() error {
	var owner string
	if !db.IgnoreForeignTables {
		if db.tableExists("state_groups_state") {
			return fmt.Errorf("%w (found state_groups_state, likely belonging to Synapse)", ErrForeignTables)
		} else if db.tableExists("goose_db_version") {
			return fmt.Errorf("%w (found goose_db_version, possibly belonging to Dendrite)", ErrForeignTables)
		}
	}
	if db.Owner == "" {
		return nil
	}

	_, err := db.Exec(createOwnerTable)
	if err != nil {
		return fmt.Errorf("failed to ensure database owner table exists: %w", err)
	}

	err = db.QueryRow("SELECT owner FROM database_owner WHERE key=0").Scan(&owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = db.Exec("INSERT INTO database_owner (owner) VALUES ($1)", db.Owner)
		if err != nil {
			return fmt.Errorf("failed to insert database owner: %w", err)
		}
	case err != nil:
		return fmt.Errorf("failed to check database owner: %w", err)
	case owner != db.Owner:
		return fmt.Errorf("%w %s", ErrNotOwned, owner)

	}
	return nil
}

func (db *Database) setVersion(tx *sql.Tx, version int) error {
	_, err := tx.Exec(fmt.Sprintf("DELETE FROM %s", db.VersionTable))
	if err != nil {
		return err
	}
	_, err = tx.Exec(fmt.Sprintf("INSERT INTO %s (version) VALUES ($1)", db.VersionTable), version)
	return err
}

func (db *Database) Upgrade() error {
	err := db.checkDatabaseOwner()
	if err != nil {
		return err
	}

	version, err := db.getVersion()
	if err != nil {
		return err
	}

	if version > len(db.UpgradeTable) {
		warning := fmt.Sprintf("currently on v%d, latest known: v%d", version, len(db.UpgradeTable))
		if db.IgnoreUnsupportedDatabase {
			db.Log.Warnfln("Unsupported database schema version: %s - continuing anyway", warning)
			return nil
		}
		return fmt.Errorf("%w: %s", ErrUnsupportedDatabaseVersion, warning)
	}

	db.Log.Infofln("Database currently on v%d, latest: v%d", version, len(db.UpgradeTable))
	for version < len(db.UpgradeTable) {
		upgradeItem := db.UpgradeTable[version]
		if upgradeItem.fn == nil {
			db.Log.Debugfln("Skipping v%d -> v%d as no upgrade function is defined", version, version+1)
			version++
			continue
		}
		db.Log.Infofln("Upgrading database from v%d to v%d: %s", version, upgradeItem.upgradesTo, upgradeItem.message)
		var tx *sql.Tx
		tx, err = db.Begin()
		if err != nil {
			return err
		}
		err = upgradeItem.fn(tx, db)
		if err != nil {
			return err
		}
		version = upgradeItem.upgradesTo
		err = db.setVersion(tx, version)
		if err != nil {
			return err
		}
		err = tx.Commit()
		if err != nil {
			return err
		}
	}
	return nil
}
