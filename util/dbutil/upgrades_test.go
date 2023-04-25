// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dbutil

import (
	"embed"
	"fmt"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

//go:embed samples/*.sql samples/output/*.sql
var rawUpgrades embed.FS

func makeTable() (tbl UpgradeTable) {
	tbl.RegisterFSPath(rawUpgrades, "samples")
	return
}

func expectVersionCheck(dialect Dialect, mock sqlmock.Sqlmock, returnVersion, returnCompat int) {
	if dialect == Postgres {
		mock.ExpectQuery(columnExistsPostgres).
			WithArgs("version", "compat").
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	} else if dialect == SQLite {
		mock.ExpectQuery(columnExistsSQLite).
			WithArgs("version", "compat").
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	}
	mock.ExpectQuery("SELECT version, compat FROM version LIMIT 1").
		WillReturnRows(sqlmock.NewRows([]string{"version", "compat"}).AddRow(returnVersion, returnCompat))
}

func expectVersionBump(dialect Dialect, mock sqlmock.Sqlmock, toVersion, toCompat int) {
	mock.ExpectExec("DELETE FROM version").
		WillReturnResult(sqlmock.NewResult(0, 1))
	q := "INSERT INTO version (version, compat) VALUES ($1, $2)"
	if dialect == SQLite {
		q = strings.ReplaceAll(q, "$1", "?1")
		q = strings.ReplaceAll(q, "$2", "?2")
	}
	mock.ExpectExec(q).
		WithArgs(toVersion, toCompat).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func testUpgrade(dialect Dialect) func(t *testing.T) {
	return func(t *testing.T) {
		conn, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)

		expectedUpgrade1, err := rawUpgrades.ReadFile(fmt.Sprintf("samples/output/01-%s.sql", dialect.String()))
		require.NoError(t, err)
		expectedUpgrade2, err := rawUpgrades.ReadFile(fmt.Sprintf("samples/output/04-%s.sql", dialect.String()))
		require.NoError(t, err)
		expectedUpgrade3, err := rawUpgrades.ReadFile(fmt.Sprintf("samples/output/05-%s.sql", dialect.String()))
		require.NoError(t, err)

		db := &Database{
			RawDB:        conn,
			Log:          NoopLogger,
			VersionTable: "version",
			Dialect:      dialect,
			UpgradeTable: makeTable(),

			IgnoreForeignTables: true,
		}
		db.loggingDB.UnderlyingExecable = conn
		db.loggingDB.db = db

		expectVersionCheck(db.Dialect, mock, 0, 0)
		mock.ExpectBegin()
		mock.ExpectExec(string(expectedUpgrade1)).
			WillReturnResult(sqlmock.NewResult(0, 0))
		expectVersionBump(db.Dialect, mock, 3, 3)
		mock.ExpectCommit()
		mock.ExpectExec(string(expectedUpgrade2)).
			WillReturnResult(sqlmock.NewResult(0, 0))
		expectVersionBump(db.Dialect, mock, 4, 4)
		mock.ExpectBegin()
		mock.ExpectExec(string(expectedUpgrade3)).
			WillReturnResult(sqlmock.NewResult(0, 0))
		expectVersionBump(db.Dialect, mock, 5, 3)
		mock.ExpectCommit()
		err = db.Upgrade()
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	}
}

func testCompatCheck(dialect Dialect) func(t *testing.T) {
	return func(t *testing.T) {
		conn, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)

		db := &Database{
			RawDB:        conn,
			Log:          NoopLogger,
			VersionTable: "version",
			Dialect:      dialect,
			UpgradeTable: makeTable(),

			IgnoreForeignTables: true,
		}
		db.loggingDB.UnderlyingExecable = conn
		db.loggingDB.db = db

		expectVersionCheck(db.Dialect, mock, 10, 5)
		err = db.Upgrade()
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())

		expectVersionCheck(db.Dialect, mock, 10, 6)
		err = db.Upgrade()
		require.ErrorIs(t, err, ErrUnsupportedDatabaseVersion)
		require.NoError(t, mock.ExpectationsWereMet())

		expectVersionCheck(db.Dialect, mock, 5, 3)
		err = db.Upgrade()
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	}
}

func TestDatabase_Upgrade(t *testing.T) {
	t.Run("SQLite", testUpgrade(SQLite))
	t.Run("Postgres", testUpgrade(Postgres))
}

func TestDatabase_Upgrade_CompatCheck(t *testing.T) {
	t.Run("SQLite", testCompatCheck(SQLite))
	t.Run("Postgres", testCompatCheck(Postgres))
}
