// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package eventauth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type pythonIntTest struct {
	Name     string
	Input    string
	Expected int64
}

var pythonIntTests = []pythonIntTest{
	{"True", `true`, 1},
	{"False", `false`, 0},
	{"SmallFloat", `3.1415`, 3},
	{"SmallFloatRoundDown", `10.999999999999999`, 10},
	{"SmallFloatRoundUp", `10.9999999999999999`, 11},
	{"BigFloatRoundDown", `1000000.9999999999`, 1000000},
	{"BigFloatRoundUp", `1000000.99999999999`, 1000001},
	{"BigFloatPrecisionError", `9007199254740993.0`, 9007199254740992},
	{"BigFloatPrecisionError2", `9007199254740993.123`, 9007199254740994},
	{"Int64", `9223372036854775807`, 9223372036854775807},
	{"Int64String", `"9223372036854775807"`, 9223372036854775807},
	{"String", `"123"`, 123},
	{"InvalidFloatInString", `"123.456"`, 0},
	{"StringWithPlusSign", `"+123"`, 123},
	{"StringWithMinusSign", `"-123"`, -123},
	{"StringWithSpaces", `"  123  "`, 123},
	{"StringWithSpacesAndSign", `"  -123  "`, -123},
	//{"StringWithUnderscores", `"123_456"`, 123456},
	//{"StringWithUnderscores", `"123_456"`, 123456},
	{"InvalidStringWithTrailingUnderscore", `"123_456_"`, 0},
	{"InvalidStringWithMultipleUnderscores", `"123__456"`, 0},
	{"InvalidStringWithLeadingUnderscore", `"_123_456"`, 0},
	{"InvalidStringWithUnderscoreAfterSign", `"+_123_456"`, 0},
	{"InvalidStringWithUnderscoreAfterSpace", `"  _123_456"`, 0},
	//{"StringWithUnderscoresAndSpaces", `"  +1_2_3_4_5_6  "`, 123456},
}

func TestParsePythonInt(t *testing.T) {
	for _, test := range pythonIntTests {
		t.Run(test.Name, func(t *testing.T) {
			output := parsePythonInt(gjson.Parse(test.Input))
			if strings.HasPrefix(test.Name, "Invalid") {
				assert.Nil(t, output)
			} else {
				require.NotNil(t, output)
				assert.Equal(t, int(test.Expected), *output)
			}
		})
	}
}
