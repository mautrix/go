// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dbutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type dialectFilterTest struct {
	name  string
	line  string
	count int
}

func TestParseDialectFilter(t *testing.T) {
	db := &Database{Dialect: SQLite}
	tests := []dialectFilterTest{
		// Own dialect always returns 1 (i.e. skip current line)
		{"Own dialect: single line", `-- only: sqlite`, 1},
		{"Own dialect: multiple lines", `-- only: sqlite for next 5 lines`, 1},
		{"Own dialect: fenced", `-- only: sqlite until "end only"`, 1},

		{"Other dialect: single line", `-- only: postgres`, 2},
		{"Other dialect: multiple lines", `-- only: postgres for next 5 lines`, 6},
		{"Other dialect: fenced", `-- only: postgres until "end only"`, -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lines, err := db.parseDialectFilter([]byte(test.line))
			assert.NoError(t, err)
			assert.Equal(t, test.count, lines)
		})
	}
}

func TestFilterSQLUpgrade(t *testing.T) {
	//	db := &Database{Dialect: Postgres}
	//	tests := []dialectFilterTest{
	//		{"Own dialect: single line", `
	//`},
	//	}
}
