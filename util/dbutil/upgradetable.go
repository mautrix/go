// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dbutil

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type UpgradeTable []upgrade

func (ut *UpgradeTable) extend(toSize int) {
	if cap(*ut) >= toSize {
		*ut = (*ut)[:toSize]
	} else {
		resized := make([]upgrade, toSize)
		copy(resized, *ut)
		*ut = resized
	}
}

func (ut *UpgradeTable) Register(from, to, compat int, message string, txn bool, fn upgradeFunc) {
	if from < 0 {
		from += to
	}
	if from < 0 {
		panic("invalid from value in UpgradeTable.Register() call")
	}
	if compat <= 0 {
		compat = to
	}
	upg := upgrade{message: message, fn: fn, upgradesTo: to, compatVersion: compat, transaction: txn}
	if len(*ut) == from {
		*ut = append(*ut, upg)
		return
	} else if len(*ut) < from {
		ut.extend(from + 1)
	} else if (*ut)[from].fn != nil {
		panic(fmt.Errorf("tried to override upgrade at %d ('%s') with '%s'", from, (*ut)[from].message, upg.message))
	}
	(*ut)[from] = upg
}

// Syntax is either
//
//	-- v0 -> v1: Message
//
// or
//
//	-- v1: Message
//
// Both syntaxes may also have a compatibility notice before the colon:
//
//	-- v5 (compatible with v3+): Upgrade with backwards compatibility
var upgradeHeaderRegex = regexp.MustCompile(`^-- (?:v(\d+) -> )?v(\d+)(?: \(compatible with v(\d+)\+\))?: (.+)$`)

// To disable wrapping the upgrade in a single transaction, put `--transaction: off` on the second line.
//
//	-- v5: Upgrade without transaction
//	-- transaction: off
//	// do dangerous stuff
var transactionDisableRegex = regexp.MustCompile(`^-- transaction: (\w*)`)

func parseFileHeader(file []byte) (from, to, compat int, message string, txn bool, lines [][]byte, err error) {
	lines = bytes.Split(file, []byte("\n"))
	if len(lines) < 2 {
		err = errors.New("upgrade file too short")
		return
	}
	var maybeFrom int
	match := upgradeHeaderRegex.FindSubmatch(lines[0])
	lines = lines[1:]
	if match == nil {
		err = errors.New("header not found")
	} else if len(match) != 5 {
		err = errors.New("unexpected number of items in regex match")
	} else if maybeFrom, err = strconv.Atoi(string(match[1])); len(match[1]) > 0 && err != nil {
		err = fmt.Errorf("invalid source version: %w", err)
	} else if to, err = strconv.Atoi(string(match[2])); err != nil {
		err = fmt.Errorf("invalid target version: %w", err)
	} else if compat, err = strconv.Atoi(string(match[3])); len(match[3]) > 0 && err != nil {
		err = fmt.Errorf("invalid compatible version: %w", err)
	} else {
		err = nil
		if len(match[1]) > 0 {
			from = maybeFrom
		} else {
			from = -1
		}
		message = string(match[4])
		txn = true
		match = transactionDisableRegex.FindSubmatch(lines[0])
		if match != nil {
			lines = lines[1:]
			if string(match[1]) != "off" {
				err = fmt.Errorf("invalid value %q for transaction flag", match[1])
			}
			txn = false
		}
	}
	return
}

// To limit the next line to one dialect:
//
//	-- only: postgres
//
// To limit the next N lines:
//
//	-- only: sqlite for next 123 lines
//
// If the single-line limit is on the second line of the file, the whole file is limited to that dialect.
var dialectLineFilter = regexp.MustCompile(`^\s*-- only: (postgres|sqlite)(?: for next (\d+) lines| until "(end) only")?`)

// Constants used to make parseDialectFilter clearer
const (
	skipUntilEndTag = -1
	skipNothing     = 0
	skipCurrentLine = 1
	skipNextLine    = 2
)

func (db *Database) parseDialectFilter(line []byte) (int, error) {
	match := dialectLineFilter.FindSubmatch(line)
	if match == nil {
		return skipNothing, nil
	}
	dialect, err := ParseDialect(string(match[1]))
	if err != nil {
		return skipNothing, err
	} else if dialect == db.Dialect {
		// Skip the dialect filter line
		return skipCurrentLine, nil
	} else if bytes.Equal(match[3], []byte("end")) {
		return skipUntilEndTag, nil
	} else if len(match[2]) == 0 {
		// Skip the dialect filter and the next line
		return skipNextLine, nil
	} else {
		// Parse number of lines to skip, add 1 for current line
		lineCount, err := strconv.Atoi(string(match[2]))
		if err != nil {
			return skipNothing, fmt.Errorf("invalid line count '%s': %w", match[2], err)
		}
		return skipCurrentLine + lineCount, nil
	}
}

var endLineFilter = regexp.MustCompile(`^\s*-- end only (postgres|sqlite)$`)

func (db *Database) filterSQLUpgrade(lines [][]byte) (string, error) {
	output := make([][]byte, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		skipLines, err := db.parseDialectFilter(lines[i])
		if err != nil {
			return "", err
		} else if skipLines > 0 {
			// Current line is implicitly skipped, so reduce one here
			i += skipLines - 1
		} else if skipLines == skipUntilEndTag {
			startedAt := i
			startedAtMatch := dialectLineFilter.FindSubmatch(lines[startedAt])
			for ; i < len(lines); i++ {
				if match := endLineFilter.FindSubmatch(lines[i]); match != nil {
					if !bytes.Equal(match[1], startedAtMatch[1]) {
						return "", fmt.Errorf(`unexpected end tag %q for %q start at line %d`, string(match[0]), string(startedAtMatch[1]), startedAt)
					}
					break
				}
			}
			if i == len(lines) {
				return "", fmt.Errorf(`didn't get end tag matching start %q at line %d`, string(startedAtMatch[1]), startedAt)
			}
		} else {
			output = append(output, lines[i])
		}
	}
	return string(bytes.Join(output, []byte("\n"))), nil
}

func sqlUpgradeFunc(fileName string, lines [][]byte) upgradeFunc {
	return func(tx Execable, db *Database) error {
		if skip, err := db.parseDialectFilter(lines[0]); err == nil && skip == skipNextLine {
			return nil
		} else if upgradeSQL, err := db.filterSQLUpgrade(lines); err != nil {
			panic(fmt.Errorf("failed to parse upgrade %s: %w", fileName, err))
		} else {
			_, err = tx.Exec(upgradeSQL)
			return err
		}
	}
}

func splitSQLUpgradeFunc(sqliteData, postgresData string) upgradeFunc {
	return func(tx Execable, database *Database) (err error) {
		switch database.Dialect {
		case SQLite:
			_, err = tx.Exec(sqliteData)
		case Postgres:
			_, err = tx.Exec(postgresData)
		default:
			err = fmt.Errorf("unknown dialect %s", database.Dialect)
		}
		return
	}
}

func parseSplitSQLUpgrade(name string, fs fullFS, skipNames map[string]struct{}) (from, to, compat int, message string, txn bool, fn upgradeFunc) {
	postgresName := fmt.Sprintf("%s.postgres.sql", name)
	sqliteName := fmt.Sprintf("%s.sqlite.sql", name)
	skipNames[postgresName] = struct{}{}
	skipNames[sqliteName] = struct{}{}
	postgresData, err := fs.ReadFile(postgresName)
	if err != nil {
		panic(err)
	}
	sqliteData, err := fs.ReadFile(sqliteName)
	if err != nil {
		panic(err)
	}
	from, to, compat, message, txn, _, err = parseFileHeader(postgresData)
	if err != nil {
		panic(fmt.Errorf("failed to parse header in %s: %w", postgresName, err))
	}
	sqliteFrom, sqliteTo, sqliteCompat, sqliteMessage, sqliteTxn, _, err := parseFileHeader(sqliteData)
	if err != nil {
		panic(fmt.Errorf("failed to parse header in %s: %w", sqliteName, err))
	}
	if from != sqliteFrom || to != sqliteTo || compat != sqliteCompat {
		panic(fmt.Errorf("mismatching versions in postgres and sqlite versions of %s: %d/%d -> %d/%d", name, from, sqliteFrom, to, sqliteTo))
	} else if message != sqliteMessage {
		panic(fmt.Errorf("mismatching message in postgres and sqlite versions of %s: %q != %q", name, message, sqliteMessage))
	} else if txn != sqliteTxn {
		panic(fmt.Errorf("mismatching transaction flag in postgres and sqlite versions of %s: %t != %t", name, txn, sqliteTxn))
	}
	fn = splitSQLUpgradeFunc(string(sqliteData), string(postgresData))
	return
}

type fullFS interface {
	fs.ReadFileFS
	fs.ReadDirFS
}

var splitFileNameRegex = regexp.MustCompile(`^(.+)\.(postgres|sqlite)\.sql$`)

func (ut *UpgradeTable) RegisterFS(fs fullFS) {
	ut.RegisterFSPath(fs, ".")
}

func (ut *UpgradeTable) RegisterFSPath(fs fullFS, dir string) {
	files, err := fs.ReadDir(dir)
	if err != nil {
		panic(err)
	}
	skipNames := map[string]struct{}{}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") {
			// do nothing
		} else if _, skip := skipNames[file.Name()]; skip {
			// also do nothing
		} else if splitName := splitFileNameRegex.FindStringSubmatch(file.Name()); splitName != nil {
			from, to, compat, message, txn, fn := parseSplitSQLUpgrade(splitName[1], fs, skipNames)
			ut.Register(from, to, compat, message, txn, fn)
		} else if data, err := fs.ReadFile(filepath.Join(dir, file.Name())); err != nil {
			panic(err)
		} else if from, to, compat, message, txn, lines, err := parseFileHeader(data); err != nil {
			panic(fmt.Errorf("failed to parse header in %s: %w", file.Name(), err))
		} else {
			ut.Register(from, to, compat, message, txn, sqlUpgradeFunc(file.Name(), lines))
		}
	}
}
