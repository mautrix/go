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
	UnderlyingExecable UnderlyingExecable
	db                 *Database
}

func (le *LoggingExecable) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	start := time.Now()
	query = le.db.mutateQuery(query)
	res, err := le.UnderlyingExecable.ExecContext(ctx, query, args...)
	le.db.Log.QueryTiming(ctx, "Exec", query, args, -1, time.Since(start), err)
	return res, err
}

func (le *LoggingExecable) QueryContext(ctx context.Context, query string, args ...interface{}) (Rows, error) {
	start := time.Now()
	query = le.db.mutateQuery(query)
	rows, err := le.UnderlyingExecable.QueryContext(ctx, query, args...)
	le.db.Log.QueryTiming(ctx, "Query", query, args, -1, time.Since(start), err)
	return &LoggingRows{
		ctx:   ctx,
		db:    le.db,
		query: query,
		args:  args,
		rs:    rows,
		start: start,
	}, err
}

func (le *LoggingExecable) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	start := time.Now()
	query = le.db.mutateQuery(query)
	row := le.UnderlyingExecable.QueryRowContext(ctx, query, args...)
	le.db.Log.QueryTiming(ctx, "QueryRow", query, args, -1, time.Since(start), nil)
	return row
}

func (le *LoggingExecable) Exec(query string, args ...interface{}) (sql.Result, error) {
	return le.ExecContext(context.Background(), query, args...)
}

func (le *LoggingExecable) Query(query string, args ...interface{}) (Rows, error) {
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
	targetDB := ld.db.RawDB
	if opts != nil && opts.ReadOnly && ld.db.ReadOnlyDB != nil {
		targetDB = ld.db.ReadOnlyDB
	}
	start := time.Now()
	tx, err := targetDB.BeginTx(ctx, opts)
	ld.db.Log.QueryTiming(ctx, "Begin", "", nil, -1, time.Since(start), err)
	if err != nil {
		return nil, err
	}
	return &LoggingTxn{
		LoggingExecable: LoggingExecable{UnderlyingExecable: tx, db: ld.db},
		UnderlyingTx:    tx,
		ctx:             ctx,
		StartTime:       start,
	}, nil
}

func (ld *loggingDB) Begin() (*LoggingTxn, error) {
	return ld.BeginTx(context.Background(), nil)
}

type LoggingTxn struct {
	LoggingExecable
	UnderlyingTx *sql.Tx
	ctx          context.Context

	StartTime  time.Time
	EndTime    time.Time
	noTotalLog bool
}

func (lt *LoggingTxn) Commit() error {
	start := time.Now()
	err := lt.UnderlyingTx.Commit()
	lt.EndTime = time.Now()
	if !lt.noTotalLog {
		lt.db.Log.QueryTiming(lt.ctx, "<Transaction>", "", nil, -1, lt.EndTime.Sub(lt.StartTime), nil)
	}
	lt.db.Log.QueryTiming(lt.ctx, "Commit", "", nil, -1, time.Since(start), err)
	return err
}

func (lt *LoggingTxn) Rollback() error {
	start := time.Now()
	err := lt.UnderlyingTx.Rollback()
	lt.EndTime = time.Now()
	if !lt.noTotalLog {
		lt.db.Log.QueryTiming(lt.ctx, "<Transaction>", "", nil, -1, lt.EndTime.Sub(lt.StartTime), nil)
	}
	lt.db.Log.QueryTiming(lt.ctx, "Rollback", "", nil, -1, time.Since(start), err)
	return err
}

type LoggingRows struct {
	ctx   context.Context
	db    *Database
	query string
	args  []interface{}
	rs    Rows
	start time.Time
	nrows int
}

func (lrs *LoggingRows) stopTiming() {
	if !lrs.start.IsZero() {
		lrs.db.Log.QueryTiming(lrs.ctx, "EndRows", lrs.query, lrs.args, lrs.nrows, time.Since(lrs.start), lrs.rs.Err())
		lrs.start = time.Time{}
	}
}

func (lrs *LoggingRows) Close() error {
	err := lrs.rs.Close()
	lrs.stopTiming()
	return err
}

func (lrs *LoggingRows) ColumnTypes() ([]*sql.ColumnType, error) {
	return lrs.rs.ColumnTypes()
}

func (lrs *LoggingRows) Columns() ([]string, error) {
	return lrs.rs.Columns()
}

func (lrs *LoggingRows) Err() error {
	return lrs.rs.Err()
}

func (lrs *LoggingRows) Next() bool {
	hasNext := lrs.rs.Next()

	if !hasNext {
		lrs.stopTiming()
	} else {
		lrs.nrows++
	}

	return hasNext
}

func (lrs *LoggingRows) NextResultSet() bool {
	hasNext := lrs.rs.NextResultSet()

	if !hasNext {
		lrs.stopTiming()
	} else {
		lrs.nrows++
	}

	return hasNext
}

func (lrs *LoggingRows) Scan(dest ...any) error {
	return lrs.rs.Scan(dest...)
}
