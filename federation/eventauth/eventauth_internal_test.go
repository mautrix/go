// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package eventauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type pythonIntTest struct {
	Name     string
	Input    string
	Expected int
	Invalid  bool
}

var pythonIntTests = []pythonIntTest{
	{"True", `true`, 1, false},
	{"False", `false`, 0, false},
	{"SmallFloat", `3.1415`, 3, false},
	{"SmallFloatRoundDown", `10.999999999999999`, 10, false},
	{"SmallFloatRoundUp", `10.9999999999999999`, 11, false},
	{"BigFloatRoundDown", `1000000.9999999999`, 1000000, false},
	{"BigFloatRoundUp", `1000000.99999999999`, 1000001, false},
	{"String", `"123"`, 123, false},
	{"FloatInString", `"123.456"`, 0, true},
	{"StringWithPlusSign", `"+123"`, 123, false},
	{"StringWithMinusSign", `"-123"`, -123, false},
	{"StringWithSpaces", `"  123  "`, 123, false},
	{"StringWithSpacesAndSign", `"  -123  "`, -123, false},
	{"StringWithUnderscores", `"123_456"`, 123456, false},
	{"StringWithUnderscores", `"123_456"`, 123456, false},
	{"StringWithTrailingUnderscore", `"123_456_"`, 0, true},
	{"StringWithLeadingUnderscore", `"_123_456"`, 0, true},
	{"StringWithUnderscoreAfterSign", `"+_123_456"`, 0, true},
	{"StringWithUnderscoreAfterSpace", `"  _123_456"`, 0, true},
	{"StringWithUnderscoresAndSpaces", `"  +1_2_3_4_5_6  "`, 123456, false},
}

func TestParsePythonInt(t *testing.T) {
	for _, test := range pythonIntTests {
		t.Run(test.Name, func(t *testing.T) {
			output := parsePythonInt(gjson.Parse(test.Input))
			if test.Invalid {
				assert.Nil(t, output)
			} else {
				require.NotNil(t, output)
				assert.Equal(t, test.Expected, *output)
			}
		})
	}
}
