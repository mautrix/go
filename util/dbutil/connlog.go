// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dbutil

import (
	"context"
	"database/sql"
	"time"
)

// LoggingExecable is a wrapper for anything with database Exec methods (i.e. sql.Conn, sql.DB and sql.Tx)
// that can preprocess queries (e.g. replacing $ with ? on SQLite) and log query durations.
type LoggingExecable struct {
	UnderlyingExecable Execable
	db                 *Database
}

func (le *LoggingExecable) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	start := time.Now()
	query = le.db.mutateQuery(query)
	res, err := le.UnderlyingExecable.ExecContext(ctx, query, args...)
	le.db.Log.QueryTiming(ctx, "Exec", query, args, time.Since(start))
	return res, err
}

func (le *LoggingExecable) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	start := time.Now()
	query = le.db.mutateQuery(query)
	rows, err := le.UnderlyingExecable.QueryContext(ctx, query, args...)
	le.db.Log.QueryTiming(ctx, "Query", query, args, time.Since(start))
	return rows, err
}

func (le *LoggingExecable) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	start := time.Now()
	query = le.db.mutateQuery(query)
	row := le.UnderlyingExecable.QueryRowContext(ctx, query, args...)
	le.db.Log.QueryTiming(ctx, "QueryRow", query, args, time.Since(start))
	return row
}

func (le *LoggingExecable) Exec(query string, args ...interface{}) (sql.Result, error) {
	return le.ExecContext(context.Background(), query, args...)
}

func (le *LoggingExecable) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return le.QueryContext(context.Background(), query, args...)
}

func (le *LoggingExecable) QueryRow(query string, args ...interface{}) *sql.Row {
	return le.QueryRowContext(context.Background(), query, args...)
}

// loggingDB is a wrapper for LoggingExecable that allows access to BeginTx.
//
// While LoggingExecable has a pointer to the database and could use BeginTx, it's not technically safe since
// the LoggingExecable could be for a transaction (where BeginTx wouldn't make sense).
type loggingDB struct {
	LoggingExecable
}

func (ld *loggingDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*LoggingTxn, error) {
	start := time.Now()
	tx, err := ld.db.RawDB.BeginTx(ctx, opts)
	ld.db.Log.QueryTiming(ctx, "Begin", "", nil, time.Since(start))
	if err != nil {
		return nil, err
	}
	return &LoggingTxn{
		LoggingExecable: LoggingExecable{UnderlyingExecable: tx, db: ld.db},
		UnderlyingTx:    tx,
		ctx:             ctx,
	}, nil
}

func (ld *loggingDB) Begin() (*LoggingTxn, error) {
	return ld.BeginTx(context.Background(), nil)
}

type LoggingTxn struct {
	LoggingExecable
	UnderlyingTx *sql.Tx
	ctx          context.Context
}

func (lt *LoggingTxn) Commit() error {
	start := time.Now()
	err := lt.UnderlyingTx.Commit()
	lt.db.Log.QueryTiming(lt.ctx, "Commit", "", nil, time.Since(start))
	return err
}

func (lt *LoggingTxn) Rollback() error {
	start := time.Now()
	err := lt.UnderlyingTx.Rollback()
	lt.db.Log.QueryTiming(lt.ctx, "Rollback", "", nil, time.Since(start))
	return err
}
