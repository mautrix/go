// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dbutil

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	log "maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix/bridge/bridgeconfig"
)

type Dialect int

const (
	DialectUnknown Dialect = iota
	Postgres
	SQLite
)

func (dialect Dialect) String() string {
	switch dialect {
	case Postgres:
		return "postgres"
	case SQLite:
		return "sqlite3"
	default:
		return ""
	}
}

func ParseDialect(engine string) (Dialect, error) {
	switch strings.ToLower(engine) {
	case "postgres", "postgresql":
		return Postgres, nil
	case "sqlite3", "sqlite":
		return SQLite, nil
	default:
		return DialectUnknown, fmt.Errorf("unknown dialect '%s'", engine)
	}
}

type Scannable interface {
	Scan(...interface{}) error
}

type Execable interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

type Database struct {
	*sql.DB
	Owner        string
	VersionTable string
	Log          log.Logger
	Dialect      Dialect
	UpgradeTable UpgradeTable

	IgnoreForeignTables       bool
	IgnoreUnsupportedDatabase bool
}

func (db *Database) Child(logName, versionTable string, upgradeTable UpgradeTable) *Database {
	return &Database{
		DB:           db.DB,
		Owner:        "",
		VersionTable: versionTable,
		UpgradeTable: upgradeTable,
		Log:          db.Log.Sub(logName),
		Dialect:      db.Dialect,

		IgnoreForeignTables:       true,
		IgnoreUnsupportedDatabase: db.IgnoreUnsupportedDatabase,
	}
}

func NewWithDB(db *sql.DB, rawDialect string) (*Database, error) {
	dialect, err := ParseDialect(rawDialect)
	if err != nil {
		return nil, err
	}
	return &Database{
		DB:      db,
		Dialect: dialect,
		Log:     log.Sub("Database"),

		IgnoreForeignTables: true,
		VersionTable:        "version",
	}, nil
}

func NewWithDialect(uri, rawDialect string) (*Database, error) {
	db, err := sql.Open(rawDialect, uri)
	if err != nil {
		return nil, err
	}
	return NewWithDB(db, rawDialect)
}

func NewFromConfig(owner string, cfg bridgeconfig.DatabaseConfig, dbLog log.Logger) (*Database, error) {
	dialect, err := ParseDialect(cfg.Type)
	if err != nil {
		return nil, err
	}
	conn, err := sql.Open(cfg.Type, cfg.URI)
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(cfg.MaxOpenConns)
	conn.SetMaxIdleConns(cfg.MaxIdleConns)
	if len(cfg.ConnMaxIdleTime) > 0 {
		maxIdleTimeDuration, err := time.ParseDuration(cfg.ConnMaxIdleTime)
		if err != nil {
			return nil, fmt.Errorf("failed to parse max_conn_idle_time: %w", err)
		}
		conn.SetConnMaxIdleTime(maxIdleTimeDuration)
	}
	if len(cfg.ConnMaxLifetime) > 0 {
		maxLifetimeDuration, err := time.ParseDuration(cfg.ConnMaxLifetime)
		if err != nil {
			return nil, fmt.Errorf("failed to parse max_conn_idle_time: %w", err)
		}
		conn.SetConnMaxLifetime(maxLifetimeDuration)
	}
	if dbLog == nil {
		dbLog = log.Sub("Database")
	}
	return &Database{
		DB:      conn,
		Owner:   owner,
		Log:     dbLog,
		Dialect: dialect,

		IgnoreForeignTables: true,
		VersionTable:        "version",
	}, nil
}
