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
	"net/url"
	"regexp"
	"strings"
	"time"
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
	engine = strings.ToLower(engine)

	if strings.HasPrefix(engine, "postgres") || engine == "pgx" {
		return Postgres, nil
	} else if strings.HasPrefix(engine, "sqlite") || strings.HasPrefix(engine, "litestream") {
		return SQLite, nil
	} else {
		return DialectUnknown, fmt.Errorf("unknown dialect '%s'", engine)
	}
}

type Rows interface {
	Close() error
	ColumnTypes() ([]*sql.ColumnType, error)
	Columns() ([]string, error)
	Err() error
	Next() bool
	NextResultSet() bool
	Scan(...any) error
}

type Scannable interface {
	Scan(...interface{}) error
}

// Expected implementations of Scannable
var (
	_ Scannable = (*sql.Row)(nil)
	_ Scannable = (Rows)(nil)
)

type UnderlyingContextExecable interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

type ContextExecable interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

type UnderlyingExecable interface {
	UnderlyingContextExecable
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

type Execable interface {
	ContextExecable
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

type Transaction interface {
	Execable
	Commit() error
	Rollback() error
}

// Expected implementations of Execable
var (
	_ UnderlyingExecable        = (*sql.Tx)(nil)
	_ UnderlyingExecable        = (*sql.DB)(nil)
	_ Execable                  = (*LoggingExecable)(nil)
	_ Transaction               = (*LoggingTxn)(nil)
	_ UnderlyingContextExecable = (*sql.Conn)(nil)
)

type Database struct {
	loggingDB
	RawDB        *sql.DB
	ReadOnlyDB   *sql.DB
	Owner        string
	VersionTable string
	Log          DatabaseLogger
	Dialect      Dialect
	UpgradeTable UpgradeTable

	IgnoreForeignTables       bool
	IgnoreUnsupportedDatabase bool
}

var positionalParamPattern = regexp.MustCompile(`\$(\d+)`)

func (db *Database) mutateQuery(query string) string {
	switch db.Dialect {
	case SQLite:
		return positionalParamPattern.ReplaceAllString(query, "?$1")
	default:
		return query
	}
}

func (db *Database) Child(versionTable string, upgradeTable UpgradeTable, log DatabaseLogger) *Database {
	if log == nil {
		log = db.Log
	}
	return &Database{
		RawDB:        db.RawDB,
		loggingDB:    db.loggingDB,
		Owner:        "",
		VersionTable: versionTable,
		UpgradeTable: upgradeTable,
		Log:          log,
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
	wrappedDB := &Database{
		RawDB:   db,
		Dialect: dialect,
		Log:     NoopLogger,

		IgnoreForeignTables: true,
		VersionTable:        "version",
	}
	wrappedDB.loggingDB.UnderlyingExecable = db
	wrappedDB.loggingDB.db = wrappedDB
	return wrappedDB, nil
}

func NewWithDialect(uri, rawDialect string) (*Database, error) {
	db, err := sql.Open(rawDialect, uri)
	if err != nil {
		return nil, err
	}

	return NewWithDB(db, rawDialect)
}

type PoolConfig struct {
	Type string `yaml:"type"`
	URI  string `yaml:"uri"`

	MaxOpenConns int `yaml:"max_open_conns"`
	MaxIdleConns int `yaml:"max_idle_conns"`

	ConnMaxIdleTime string `yaml:"conn_max_idle_time"`
	ConnMaxLifetime string `yaml:"conn_max_lifetime"`
}

type Config struct {
	PoolConfig   `yaml:",inline"`
	ReadOnlyPool PoolConfig `yaml:"ro_pool"`
}

func (db *Database) Close() error {
	err := db.RawDB.Close()
	if db.ReadOnlyDB != nil {
		err2 := db.ReadOnlyDB.Close()
		if err == nil {
			err = fmt.Errorf("closing read-only db failed: %w", err)
		} else {
			err = fmt.Errorf("%w (closing read-only db also failed: %v)", err, err2)
		}
	}
	return err
}

func (db *Database) Configure(cfg Config) error {
	if err := db.configure(db.ReadOnlyDB, cfg.ReadOnlyPool); err != nil {
		return err
	}

	return db.configure(db.RawDB, cfg.PoolConfig)
}

func (db *Database) configure(rawDB *sql.DB, cfg PoolConfig) error {
	if rawDB == nil {
		return nil
	}

	rawDB.SetMaxOpenConns(cfg.MaxOpenConns)
	rawDB.SetMaxIdleConns(cfg.MaxIdleConns)
	if len(cfg.ConnMaxIdleTime) > 0 {
		maxIdleTimeDuration, err := time.ParseDuration(cfg.ConnMaxIdleTime)
		if err != nil {
			return fmt.Errorf("failed to parse max_conn_idle_time: %w", err)
		}
		rawDB.SetConnMaxIdleTime(maxIdleTimeDuration)
	}
	if len(cfg.ConnMaxLifetime) > 0 {
		maxLifetimeDuration, err := time.ParseDuration(cfg.ConnMaxLifetime)
		if err != nil {
			return fmt.Errorf("failed to parse max_conn_idle_time: %w", err)
		}
		rawDB.SetConnMaxLifetime(maxLifetimeDuration)
	}
	return nil
}

func NewFromConfig(owner string, cfg Config, logger DatabaseLogger) (*Database, error) {
	wrappedDB, err := NewWithDialect(cfg.URI, cfg.Type)
	if err != nil {
		return nil, err
	}

	wrappedDB.Owner = owner
	if logger != nil {
		wrappedDB.Log = logger
	}

	if cfg.ReadOnlyPool.MaxOpenConns > 0 {
		if cfg.ReadOnlyPool.Type == "" {
			cfg.ReadOnlyPool.Type = cfg.Type
		}

		roUri := cfg.ReadOnlyPool.URI
		if roUri == "" {
			uriParts := strings.Split(cfg.URI, "?")

			var qs url.Values
			if len(uriParts) == 2 {
				var err error
				qs, err = url.ParseQuery(uriParts[1])
				if err != nil {
					return nil, err
				}

				qs.Del("_txlock")
			}
			qs.Set("_query_only", "true")

			roUri = uriParts[0] + "?" + qs.Encode()
		}

		wrappedDB.ReadOnlyDB, err = sql.Open(cfg.ReadOnlyPool.Type, roUri)
		if err != nil {
			return nil, err
		}
	}

	err = wrappedDB.Configure(cfg)
	if err != nil {
		return nil, err
	}

	return wrappedDB, nil
}
