// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dbutil

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
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

func (ut *UpgradeTable) Register(from, to int, message string, fn upgradeFunc) {
	if from < 0 {
		from += to
	}
	if from < 0 {
		panic("invalid from value in UpgradeTable.Register() call")
	}
	upg := upgrade{message: message, fn: fn, upgradesTo: to}
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
//   -- v0 -> v1: Message
// or
//   -- v1: Message
var upgradeHeaderRegex = regexp.MustCompile(`^-- (?:v(\d+) -> )?v(\d+): (.+)$`)

func parseFileHeader(file []byte) (from, to int, message string, lines [][]byte, err error) {
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
	} else if len(match) != 4 {
		err = errors.New("unexpected number of items in regex match")
	} else if maybeFrom, err = strconv.Atoi(string(match[1])); len(match[1]) > 0 && err != nil {
		err = fmt.Errorf("invalid source version: %w", err)
	} else if to, err = strconv.Atoi(string(match[2])); err != nil {
		err = fmt.Errorf("invalid target version: %w", err)
	} else {
		if len(match[1]) > 0 {
			from = maybeFrom
		} else {
			from = -1
		}
		message = string(match[3])
	}
	return
}

// To limit the next line to one dialect:
//   -- only: postgres
// To limit the next N lines:
//   -- only: sqlite for next 123 lines
// If the single-line limit is on the second line of the file, the whole file is limited to that dialect.
var dialectLineFilter = regexp.MustCompile(`^\s*-- only: (postgres|sqlite)(?: for next (\d+) lines)?`)

func (db *Database) parseDialectFilter(line []byte) (int, error) {
	match := dialectLineFilter.FindSubmatch(line)
	if match != nil {
		dialect, err := ParseDialect(string(match[1]))
		if err != nil {
			return 0, err
		} else if dialect != db.Dialect {
			if len(match[2]) == 0 {
				return 1, nil
			}
			lineCount, err := strconv.Atoi(string(match[2]))
			if err != nil {
				return 0, fmt.Errorf("invalid line count '%s': %w", match[2], err)
			}
			return lineCount, nil
		}
	}
	return 0, nil
}

func (db *Database) mutateSQLUpgrade(lines [][]byte) (string, error) {
	output := lines[:0]
	for i := 0; i < len(lines); i++ {
		skipLines, err := db.parseDialectFilter(lines[i])
		if err != nil {
			return "", err
		} else if skipLines > 0 {
			i += skipLines
		} else {
			output = append(output, lines[i])
		}
	}
	return string(bytes.Join(output, []byte("\n"))), nil
}

func sqlUpgradeFunc(fileName string, lines [][]byte) upgradeFunc {
	return func(tx *sql.Tx, db *Database) error {
		if skip, err := db.parseDialectFilter(lines[0]); err == nil && skip == 1 {
			return nil
		} else if upgradeSQL, err := db.mutateSQLUpgrade(lines); err != nil {
			panic(fmt.Errorf("failed to parse upgrade %s: %w", fileName, err))
		} else {
			_, err = tx.Exec(upgradeSQL)
			return err
		}
	}
}

type fullFS interface {
	fs.ReadFileFS
	fs.ReadDirFS
}

func (ut *UpgradeTable) RegisterFS(fs fullFS) {
	files, err := fs.ReadDir(".")
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		if data, err := fs.ReadFile(file.Name()); err != nil {
			panic(err)
		} else if from, to, message, lines, err := parseFileHeader(data); err != nil {
			panic(fmt.Errorf("failed to parse header in %s: %w", file.Name(), err))
		} else {
			ut.Register(from, to, message, sqlUpgradeFunc(file.Name(), lines))
		}
	}
}
