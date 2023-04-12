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
)

type upgradeFunc func(Execable, *Database) error

type upgrade struct {
	message string
	fn      upgradeFunc

	upgradesTo  int
	transaction bool
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
const tableExistsSQLite = "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND tbl_name=$1)"

func (db *Database) TableExists(tx Execable, table string) (exists bool, err error) {
	if tx == nil {
		tx = db
	}
	if db.Dialect == SQLite {
		err = db.QueryRow(tableExistsSQLite, table).Scan(&exists)
	} else if db.Dialect == Postgres {
		err = db.QueryRow(tableExistsPostgres, table).Scan(&exists)
	}
	return
}

func (db *Database) tableExistsNoError(table string) bool {
	exists, err := db.TableExists(nil, table)
	if err != nil {
		panic(fmt.Errorf("failed to check if table exists: %w", err))
	}
	return exists
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
		if db.tableExistsNoError("state_groups_state") {
			return fmt.Errorf("%w (found state_groups_state, likely belonging to Synapse)", ErrForeignTables)
		} else if db.tableExistsNoError("roomserver_rooms") {
			return fmt.Errorf("%w (found roomserver_rooms, likely belonging to Dendrite)", ErrForeignTables)
		}
	}
	if db.Owner == "" {
		return nil
	}
	if _, err := db.Exec(createOwnerTable); err != nil {
		return fmt.Errorf("failed to ensure database owner table exists: %w", err)
	} else if err = db.QueryRow("SELECT owner FROM database_owner WHERE key=0").Scan(&owner); errors.Is(err, sql.ErrNoRows) {
		_, err = db.Exec("INSERT INTO database_owner (key, owner) VALUES (0, $1)", db.Owner)
		if err != nil {
			return fmt.Errorf("failed to insert database owner: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check database owner: %w", err)
	} else if owner != db.Owner {
		return fmt.Errorf("%w %s", ErrNotOwned, owner)
	}
	return nil
}

func (db *Database) setVersion(tx Execable, version int) error {
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
		if db.IgnoreUnsupportedDatabase {
			db.Log.WarnUnsupportedVersion(version, len(db.UpgradeTable))
			return nil
		}
		return fmt.Errorf("%w: currently on v%d, latest known: v%d", ErrUnsupportedDatabaseVersion, version, len(db.UpgradeTable))
	}

	db.Log.PrepareUpgrade(version, len(db.UpgradeTable))
	logVersion := version
	for version < len(db.UpgradeTable) {
		upgradeItem := db.UpgradeTable[version]
		if upgradeItem.fn == nil {
			version++
			continue
		}
		db.Log.DoUpgrade(logVersion, upgradeItem.upgradesTo, upgradeItem.message, upgradeItem.transaction)
		var tx Transaction
		var upgradeConn Execable
		if upgradeItem.transaction {
			tx, err = db.Begin()
			if err != nil {
				return err
			}
			upgradeConn = tx
		} else {
			upgradeConn = db
		}
		err = upgradeItem.fn(upgradeConn, db)
		if err != nil {
			return err
		}
		version = upgradeItem.upgradesTo
		logVersion = version
		err = db.setVersion(upgradeConn, version)
		if err != nil {
			return err
		}
		if tx != nil {
			err = tx.Commit()
			if err != nil {
				return err
			}
		}
	}
	return nil
}
