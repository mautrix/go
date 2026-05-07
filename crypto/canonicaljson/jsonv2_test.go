// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package canonicaljson_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/canonicaljson"
)

var canonicalizeTests = []struct {
	input string
	want  string
}{
	{"{}", "{}"},
	{`[{"b":"two","a":1}]`, `[{"a":1,"b":"two"}]`},
	{`{"B":{"4":4,"3":3},"A":{"1":1,"2":2}}`, `{"A":{"1":1,"2":2},"B":{"3":3,"4":4}}`},
	{`[true,false,null]`, `[true,false,null]`},
	{`[9007199254740991]`, `[9007199254740991]`},
	{"\t\n[9007199254740991]", `[9007199254740991]`},
	{`[true,false,null]`, `[true,false,null]`},
	{`[{"b":"two","a":1}]`, `[{"a":1,"b":"two"}]`},
	{`{"B":{"4":4,"3":3},"A":{"1":1,"2":2}}`, `{"A":{"1":1,"2":2},"B":{"3":3,"4":4}}`},
	{`[true,false,null]`, `[true,false,null]`},
	{`[9007199254740991]`, `[9007199254740991]`},
	{`[-9007199254740991]`, `[-9007199254740991]`},
	{"\t\n[9007199254740991]", `[9007199254740991]`},
	{`[true,false,null]`, `[true,false,null]`},
	{`"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007"`, `"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007"`},
	{`"\u0008\u0009\u000A\u000B\u000C\u000D\u000E\u000F"`, `"\b\t\n\u000b\f\r\u000e\u000f"`},
	{`"\b\t\n\u000B\f\r\u000E\u000F"`, `"\b\t\n\u000b\f\r\u000e\u000f"`},
	{`"\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017"`, `"\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017"`},
	{`"\u0018\u0019\u001A\u001B\u001C\u001D\u001E\u001F"`, `"\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f"`},
	{`["\u0061\u005C\u0042\u0022"]`, `["a\\B\""]`},
	{`"\u0120"`, "\"\u0120\""},
	{`"\u0FFF"`, "\"\u0FFF\""},
	{`"\u1820"`, "\"\u1820\""},
	{`"\uFFFF"`, "\"\uFFFF\""},
	{`"\uD842\uDC20"`, "\"\U00020820\""},
	{`"\uDBFF\uDFFF"`, "\"\U0010FFFF\""},
	{`{"a": 1.0}`, `{"a":1}`},
	{`{"a": 0.0}`, `{"a":0}`},
	{`{"a": -0.0}`, `{"a":0}`},
	{`{"a": 1e10}`, `{"a":10000000000}`},
	{
		`{"\ud83d\udc31": "meow", "\ud800\udc00": {"\ud800\udc00": "hmm1", "\uffff": "meowo1", "\ud800\udc01": "hmm2", "\uefff": "meowo2"}, "\uf123": "woof"}`,
		"{\"\uf123\":\"woof\",\"\U00010000\":{\"\uEFFF\":\"meowo2\",\"\uFFFF\":\"meowo1\",\"\U00010000\":\"hmm1\",\"\U00010001\":\"hmm2\"},\"\U0001F431\":\"meow\"}",
	},
}

func TestCanonicalize(t *testing.T) {
	for _, test := range canonicalizeTests {
		t.Run(test.input, func(t *testing.T) {
			val := jsontext.Value(test.input)
			err := canonicaljson.Canonicalize(&val)
			assert.NoError(t, err)
			assert.Equal(t, test.want, string(val))
		})
	}
}

func TestMarshal_Roundtrip(t *testing.T) {
	for _, test := range canonicalizeTests {
		t.Run(test.input, func(t *testing.T) {
			// Unmarshal preserves negative zeroes, so Marshal will reject it,
			// while Canonicalize will accept it and convert to a plain zero.
			// Both behaviors are acceptable, so skip the test here.
			if test.input == `{"a": -0.0}` {
				t.SkipNow()
			}
			var temp any
			require.NoError(t, json.Unmarshal([]byte(test.input), &temp))
			val, err := canonicaljson.Marshal(temp)
			require.NoError(t, err)
			assert.Equal(t, test.want, string(val))
		})
	}
}

type m = map[string]any

func TestMarshal(t *testing.T) {
	var tests = []struct {
		name  string
		input m
		want  string
	}{
		{"empty object", m{}, `{}`},
		{"simple types", m{"c": nil, "d": "foo", "e": 1234, "a": true, "b": false}, `{"a":true,"b":false,"c":null,"d":"foo","e":1234}`},
		// TODO more tests
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := canonicaljson.Marshal(test.input)
			assert.NoError(t, err)
			assert.Equal(t, test.want, string(got))
		})
	}
}

func TestCanonicalize_Error(t *testing.T) {
	var tests = []struct {
		name  string
		input string
	}{
		{"duplicate keys", `{"a":1,"a":2}`},
		{"invalid UTF-8", "\"\xff\xfe\xfd\""},
		{"lone surrogate", `"\uD800"`},
		{"floating point number", `{"a": 1.2}`},
		{"too large number", `{"a": 9007199254740992}`},
		{"too small number", `{"a": -9007199254740992}`},
		{"zero-prefixed negative number", `{"a": -010}`},
		{"zero-prefixed number", `{"a": 010}`},
		{"big exponent number", `{"a": 1e100}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			val := jsontext.Value(test.input)
			err := canonicaljson.Canonicalize(&val)
			assert.Error(t, err)
		})
	}
}

func TestMarshal_Error(t *testing.T) {
	var tests = []struct {
		name  string
		input m
	}{
		{"invalid UTF-8", m{"a": "\xff\xfe\xfd"}},
		{"floating point number", m{"a": 1.2}},
		{"too large number", m{"a": 9007199254740992}},
		{"too small number", m{"a": -9007199254740992}},
		{"big exponent number", m{"a": 1e100}},
		{"negative zero", m{"a": math.Copysign(0, -1)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := canonicaljson.Marshal(test.input)
			assert.Error(t, err)
		})
	}
}
