// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mxmain

import (
	"errors"
	"os"

	"github.com/lib/pq"
	"github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"

	"go.mau.fi/util/dbutil"
)

type zerologPQError pq.Error

func (zpe *zerologPQError) MarshalZerologObject(evt *zerolog.Event) {
	maybeStr := func(field, value string) {
		if value != "" {
			evt.Str(field, value)
		}
	}
	maybeStr("severity", zpe.Severity)
	if name := zpe.Code.Name(); name != "" {
		evt.Str("code", name)
	} else if zpe.Code != "" {
		evt.Str("code", string(zpe.Code))
	}
	//maybeStr("message", zpe.Message)
	maybeStr("detail", zpe.Detail)
	maybeStr("hint", zpe.Hint)
	maybeStr("position", zpe.Position)
	maybeStr("internal_position", zpe.InternalPosition)
	maybeStr("internal_query", zpe.InternalQuery)
	maybeStr("where", zpe.Where)
	maybeStr("schema", zpe.Schema)
	maybeStr("table", zpe.Table)
	maybeStr("column", zpe.Column)
	maybeStr("data_type_name", zpe.DataTypeName)
	maybeStr("constraint", zpe.Constraint)
	maybeStr("file", zpe.File)
	maybeStr("line", zpe.Line)
	maybeStr("routine", zpe.Routine)
}

func (br *BridgeMain) LogDBUpgradeErrorAndExit(name string, err error, message string) {
	logEvt := br.Log.WithLevel(zerolog.FatalLevel).
		Err(err).
		Str("db_section", name)
	var errWithLine *dbutil.PQErrorWithLine
	if errors.As(err, &errWithLine) {
		logEvt.Str("sql_line", errWithLine.Line)
	}
	var pqe *pq.Error
	if errors.As(err, &pqe) {
		logEvt.Object("pq_error", (*zerologPQError)(pqe))
	}
	logEvt.Msg(message)
	if sqlError := (&sqlite3.Error{}); errors.As(err, sqlError) && sqlError.Code == sqlite3.ErrCorrupt {
		os.Exit(18)
	} else if errors.Is(err, dbutil.ErrForeignTables) {
		br.Log.Info().Msg("See https://docs.mau.fi/faq/foreign-tables for more info")
	} else if errors.Is(err, dbutil.ErrNotOwned) {
		br.Log.Info().Msg("Sharing the same database with different programs is not supported")
	} else if errors.Is(err, dbutil.ErrUnsupportedDatabaseVersion) {
		br.Log.Info().Msg("Downgrading the bridge is not supported")
	}
	os.Exit(15)
}
