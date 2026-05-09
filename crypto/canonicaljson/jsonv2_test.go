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
	name  string
	input string
	want  string
}{
	{"empty object", "{}", "{}"},
	{"reorder in array", `[{"b":"two","a":1}]`, `[{"a":1,"b":"two"}]`},
	{"nested object reorder", `{"B":{"4":4,"3":3},"A":{"1":1,"2":2}}`, `{"A":{"1":1,"2":2},"B":{"3":3,"4":4}}`},
	{"array with primitives", `[true,false,null]`, `[true,false,null]`},
	{"array with big number", `[9007199254740991]`, `[9007199254740991]`},
	{"array with small number", `[-9007199254740991]`, `[-9007199254740991]`},
	{"extra whitespace", "\t\n[9007199254740991]", `[9007199254740991]`},
	{"ascii 0-7", `"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007"`, `"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007"`},
	{"ascii 8-f expanded", `"\u0008\u0009\u000A\u000B\u000C\u000D\u000E\u000F"`, `"\b\t\n\u000b\f\r\u000e\u000f"`},
	{"ascii 8-f already correct", `"\b\t\n\u000B\f\r\u000E\u000F"`, `"\b\t\n\u000b\f\r\u000e\u000f"`},
	{"ascii 10-17", `"\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017"`, `"\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017"`},
	{"ascii 18-1f", `"\u0018\u0019\u001A\u001B\u001C\u001D\u001E\u001F"`, `"\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f"`},
	{"quote and backslash expanded", `["\u0061\u005C\u0042\u0022"]`, `["a\\B\""]`},
	{"quote and backslash already correct", `["a\\B\""]`, `["a\\B\""]`},
	{"misc unicode escapes", `"\u0120\u0FFF\u1820\uFFFF"`, "\"\u0120\u0FFF\u1820\uFFFF\""},
	{"utf-16 surrogates", `["\uD842\uDC20", "\uDBFF\uDFFF"]`, "[\"\U00020820\",\"\U0010FFFF\"]"},
	{"1.0", `{"a": 1.0}`, `{"a":1}`},
	{"0.0", `{"a": 0.0}`, `{"a":0}`},
	{"-0.0", `{"a": -0.0}`, `{"a":0}`},
	{"1e10", `{"a": 1e10}`, `{"a":10000000000}`},
	{
		"sorting where utf-8 and utf-16 disagree",
		`{"\ud83d\udc31": "meow", "\ud800\udc00": {"\ud800\udc00": "hmm1", "\uFFFF": "meowo1", "\ud800\udc01": "hmm2", "\uEFFF": "meowo2"}, "\uf123": "woof"}`,
		"{\"\uf123\":\"woof\",\"\U00010000\":{\"\uEFFF\":\"meowo2\",\"\uFFFF\":\"meowo1\",\"\U00010000\":\"hmm1\",\"\U00010001\":\"hmm2\"},\"\U0001F431\":\"meow\"}",
	},

	// Examples from the Matrix Canonical JSON spec
	// (https://spec.matrix.org/v1.18/appendices/#canonical-json).
	{"spec: simple", `{"one": 1, "two": "Two"}`, `{"one":1,"two":"Two"}`},
	{"spec: simple sort", `{"b": "2", "a": "1"}`, `{"a":"1","b":"2"}`},
	{"spec: simple sort minified", `{"b":"2","a":"1"}`, `{"a":"1","b":"2"}`},
	{
		"spec: complex nested",
		`{
    "auth": {
        "success": true,
        "mxid": "@john.doe:example.com",
        "profile": {
            "display_name": "John Doe",
            "three_pids": [
                {
                    "medium": "email",
                    "address": "john.doe@example.org"
                },
                {
                    "medium": "msisdn",
                    "address": "123456789"
                }
            ]
        }
    }
}`,
		`{"auth":{"mxid":"@john.doe:example.com","profile":{"display_name":"John Doe","three_pids":[{"address":"john.doe@example.org","medium":"email"},{"address":"123456789","medium":"msisdn"}]},"success":true}}`,
	},
	{"spec: japanese value", `{"a": "\u65e5\u672c\u8a9e"}`, "{\"a\":\"\u65e5\u672c\u8a9e\"}"},
	{"spec: japanese keys sort", `{"\u672c": 2, "\u65e5": 1}`, "{\"\u65e5\":1,\"\u672c\":2}"},
	{"spec: unicode escape to japanese", `{"a": "\u65e5"}`, "{\"a\":\"\u65e5\"}"},
	{"spec: null value", `{"a": null}`, `{"a":null}`},
	{"spec: -0 and 1e10", `{"a": -0, "b": 1e10}`, `{"a":0,"b":10000000000}`},

	// Top-level non-object values.
	{"top-level null", `null`, `null`},
	{"top-level true", `true`, `true`},
	{"top-level false", `false`, `false`},
	{"top-level number", `42`, `42`},
	{"top-level negative number", `-42`, `-42`},
	{"top-level string", `"hello"`, `"hello"`},
	{"top-level zero", `0`, `0`},

	// Empty/single containers.
	{"empty array", `[]`, `[]`},
	{"single element array", `[1]`, `[1]`},
	{"single key object", `{"a": 1}`, `{"a":1}`},
	{"empty key", `{"": 1}`, `{"":1}`},
	{"empty key empty value", `{"": ""}`, `{"":""}`},
	{"empty object as value", `{"a":{}}`, `{"a":{}}`},
	{"empty array as value", `{"a":[]}`, `{"a":[]}`},

	// Number edge cases that exercise the int53 boundary and the
	// canonicalization of various numeric representations.
	{"integer 0", `{"a": 0}`, `{"a":0}`},
	{"integer -0", `{"a": -0}`, `{"a":0}`},
	{"integer 0e0", `{"a": 0e0}`, `{"a":0}`},
	{"integer -0e0", `{"a": -0e0}`, `{"a":0}`},
	{"integer 0e10", `{"a": 0e10}`, `{"a":0}`},
	{"max safe integer", `{"a": 9007199254740991}`, `{"a":9007199254740991}`},
	{"min safe integer", `{"a": -9007199254740991}`, `{"a":-9007199254740991}`},
	{"max safe as float", `{"a": 9007199254740991.0}`, `{"a":9007199254740991}`},
	{"max safe as scientific", `{"a": 9.007199254740991e15}`, `{"a":9007199254740991}`},
	{"1e15 (within range)", `{"a": 1e15}`, `{"a":1000000000000000}`},
	{"1.5e2 to integer 150", `{"a": 1.5e2}`, `{"a":150}`},
	{"1e2 to integer 100", `{"a": 1e2}`, `{"a":100}`},
	{"explicit positive exponent", `{"a": 1.5e+2}`, `{"a":150}`},

	// Sorting edge cases. UTF-8 byte sort means uppercase precedes lowercase,
	// and shorter prefixes precede longer strings sharing those prefixes.
	{"prefix keys", `{"abc":1,"ab":2,"a":3}`, `{"a":3,"ab":2,"abc":1}`},
	{"case-sensitive sort", `{"a":1,"A":2}`, `{"A":2,"a":1}`},
	{"numeric string keys lex", `{"10":1,"2":2,"1":3}`, `{"1":3,"10":1,"2":2}`},
	{"three keys reverse", `{"c":3,"b":2,"a":1}`, `{"a":1,"b":2,"c":3}`},
	{"first element stays first", `{"a":1,"c":3,"b":2}`, `{"a":1,"b":2,"c":3}`},
	{"varying member sizes", `{"x":111111,"a":1,"m":22}`, `{"a":1,"m":22,"x":111111}`},

	// Nested structures.
	{"nested arrays with sort", `[[1,2],[3,{"b":2,"a":1}]]`, `[[1,2],[3,{"a":1,"b":2}]]`},
	{"deeply nested", `{"a":{"a":{"a":{"a":{"a":1}}}}}`, `{"a":{"a":{"a":{"a":{"a":1}}}}}`},

	// Strings.
	{"non-BMP value as escapes", `{"a":"\ud83d\udc31"}`, "{\"a\":\"\xf0\x9f\x90\xb1\"}"},
	{"non-BMP value raw", "{\"a\":\"\xf0\x9f\x90\xb1\"}", "{\"a\":\"\xf0\x9f\x90\xb1\"}"},
	{"null byte in value", `{"a":"\u0000"}`, `{"a":"\u0000"}`},
	{"DEL char raw 0x7f", "{\"a\":\"\x7f\"}", "{\"a\":\"\x7f\"}"},
	{"DEL char as escape", `{"a":"\u007f"}`, "{\"a\":\"\x7f\"}"},
}

func TestCanonicalize(t *testing.T) {
	for _, test := range canonicalizeTests {
		t.Run(test.name, func(t *testing.T) {
			val := jsontext.Value(test.input)
			err := canonicaljson.Canonicalize(&val)
			assert.NoError(t, err)
			assert.Equal(t, test.want, string(val))
		})
	}
}

// Unmarshal preserves negative zeroes, so Marshal will reject it,
// while Canonicalize will accept it and convert to a plain zero.
// Both behaviors are acceptable, so skip tests for that here.
var roundtripSkip = map[string]bool{
	"-0.0":              true,
	"integer -0":        true,
	"integer -0e0":      true,
	"spec: -0 and 1e10": true,
}

func TestMarshal_Roundtrip(t *testing.T) {
	for _, test := range canonicalizeTests {
		t.Run(test.name, func(t *testing.T) {
			if roundtripSkip[test.name] {
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

type marshalStructInner struct {
	B int `json:"b"`
	A int `json:"a"`
}

type marshalStruct struct {
	Z     int                `json:"z"`
	Inner marshalStructInner `json:"inner"`
	Name  string             `json:"name"`
}

func TestMarshal(t *testing.T) {
	var tests = []struct {
		name  string
		input any
		want  string
	}{
		{"empty object", m{}, `{}`},
		{"simple types", m{"c": nil, "d": "foo", "e": 1234, "a": true, "b": false}, `{"a":true,"b":false,"c":null,"d":"foo","e":1234}`},
		{"nil", nil, `null`},
		{"top-level true", true, `true`},
		{"top-level false", false, `false`},
		{"top-level int", 42, `42`},
		{"top-level string", "hello", `"hello"`},
		{"empty slice", []int{}, `[]`},
		{"nil slice", []int(nil), `[]`},
		{"nil map", map[string]int(nil), `{}`},
		{"slice of maps", []m{{"b": 1, "a": 2}, {"d": 3, "c": 4}}, `[{"a":2,"b":1},{"c":4,"d":3}]`},
		{"nested map", m{"b": m{"y": 1, "x": 2}, "a": 5}, `{"a":5,"b":{"x":2,"y":1}}`},
		{"struct with json tags", marshalStruct{Z: 1, Inner: marshalStructInner{B: 2, A: 3}, Name: "test"}, `{"inner":{"a":3,"b":2},"name":"test","z":1}`},
		{"mixed any slice", []any{nil, true, false, 1, "hi"}, `[null,true,false,1,"hi"]`},
		{"max safe int64", int64(9007199254740991), `9007199254740991`},
		{"min safe int64", int64(-9007199254740991), `-9007199254740991`},
		{"max safe uint64", uint64(9007199254740991), `9007199254740991`},
		{"japanese keys", m{"本": 2, "日": 1}, "{\"日\":1,\"本\":2}"},
		{"non-bmp value", m{"a": "\U0001F431"}, "{\"a\":\"\U0001F431\"}"},
		{"int 0", 0, `0`},
		{"int -1", -1, `-1`},
		{"float that is integer", 1.0, `1`},
		{"float 1e10", 1e10, `10000000000`},
		{"empty struct", struct{}{}, `{}`},
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
		{"escape-equivalent duplicate keys", `{"a":1,"\u0061":2}`},
		{"invalid UTF-8", "\"\xff\xfe\xfd\""},
		{"lone surrogate", `"\uD800"`},
		{"lone trailing surrogate", `"\uDC00"`},
		{"floating point number", `{"a": 1.2}`},
		{"plain decimal 0.1", `{"a": 0.1}`},
		{"non-integer that rounds out of range", `{"a": 9007199254740991.5}`},
		{"too large number", `{"a": 9007199254740992}`},
		{"too small number", `{"a": -9007199254740992}`},
		{"zero-prefixed negative number", `{"a": -010}`},
		{"zero-prefixed number", `{"a": 010}`},
		{"big exponent number", `{"a": 1e100}`},
		{"too large via 1e16", `{"a": 1e16}`},
		{"non-integer small exponent", `{"a": 1e-10}`},
		{"trailing comma", `{"a":1,}`},
		{"JS-style comment", `{/*hi*/"a":1}`},
		{"NaN literal", `{"a": NaN}`},
		{"Infinity literal", `{"a": Infinity}`},
		{"unquoted key", `{a:1}`},
		{"trailing data", `{}{}`},
		{"empty input", ``},
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
		input any
	}{
		{"invalid UTF-8", m{"a": "\xff\xfe\xfd"}},
		{"floating point number", m{"a": 1.2}},
		{"too large number", m{"a": 9007199254740992}},
		{"too small number", m{"a": -9007199254740992}},
		{"big exponent number", m{"a": 1e100}},
		{"negative zero", m{"a": math.Copysign(0, -1)}},
		{"NaN", m{"a": math.NaN()}},
		{"+Inf", m{"a": math.Inf(1)}},
		{"-Inf", m{"a": math.Inf(-1)}},
		{"non-integer float", m{"a": 1.5}},
		{"uint64 way too large", m{"a": ^uint64(0)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := canonicaljson.Marshal(test.input)
			assert.Error(t, err)
		})
	}
}
