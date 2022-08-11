// Copyright (c) 2022 Tulir Asokan
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

func expectVersionCheck(mock sqlmock.Sqlmock) {
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS version (version INTEGER)").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT version FROM version LIMIT 1").
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(0))
}

func expectVersionBump(dialect Dialect, mock sqlmock.Sqlmock, toVersion int) {
	mock.ExpectExec("DELETE FROM version").
		WillReturnResult(sqlmock.NewResult(0, 1))
	q := "INSERT INTO version (version) VALUES ($1)"
	if dialect == SQLite {
		q = strings.ReplaceAll(q, "$1", "?1")
	}
	mock.ExpectExec(q).
		WithArgs(toVersion).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func testUpgrade(dialect Dialect) func(t *testing.T) {
	return func(t *testing.T) {
		conn, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)

		expectedUpgrade, err := rawUpgrades.ReadFile(fmt.Sprintf("samples/output/01-%s.sql", dialect.String()))
		require.NoError(t, err)

		db := &Database{
			RawDB:        conn,
			Log:          NoopLogger,
			VersionTable: "version",
			Dialect:      dialect,
			UpgradeTable: makeTable(),
		}
		db.loggingDB.UnderlyingExecable = conn
		db.loggingDB.db = db

		expectVersionCheck(mock)
		mock.ExpectBegin()
		mock.ExpectExec(string(expectedUpgrade)).
			WillReturnResult(sqlmock.NewResult(0, 0))
		expectVersionBump(db.Dialect, mock, 3)
		mock.ExpectCommit()
		err = db.Upgrade()
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	}
}

func TestDatabase_Upgrade(t *testing.T) {
	t.Run("SQLite", testUpgrade(SQLite))
	t.Run("Postgres", testUpgrade(Postgres))
}
