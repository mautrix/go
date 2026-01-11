// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cmdschema

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mau.fi/util/exbytes"
	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/event/cmdschema/testdata"
)

type QuoteParseOutput struct {
	Parsed    string
	Remaining string
	Quoted    bool
}

func (qpo *QuoteParseOutput) UnmarshalJSON(data []byte) error {
	var arr []any
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	qpo.Parsed = arr[0].(string)
	qpo.Remaining = arr[1].(string)
	qpo.Quoted = arr[2].(bool)
	return nil
}

type QuoteParseTestData struct {
	Name   string           `json:"name"`
	Input  string           `json:"input"`
	Output QuoteParseOutput `json:"output"`
}

func loadFile[T any](name string) (into T) {
	quoteData := exerrors.Must(testdata.FS.ReadFile(name))
	exerrors.PanicIfNotNil(json.Unmarshal(quoteData, &into))
	return
}

func TestParseQuoted(t *testing.T) {
	qptd := loadFile[[]QuoteParseTestData]("parse_quote.json")
	for _, test := range qptd {
		t.Run(test.Name, func(t *testing.T) {
			parsed, remaining, quoted := parseQuoted(test.Input)
			assert.Equalf(t, test.Output, QuoteParseOutput{
				Parsed:    parsed,
				Remaining: remaining,
				Quoted:    quoted,
			}, "Failed with input `%s`", test.Input)
			// Note: can't just test that requoted == input, because some inputs
			// have unnecessary escapes which won't survive roundtripping
			t.Run("roundtrip", func(t *testing.T) {
				requoted := quoteString(parsed) + " " + remaining
				reparsed, newRemaining, _ := parseQuoted(requoted)
				assert.Equal(t, parsed, reparsed)
				assert.Equal(t, remaining, newRemaining)
			})
		})
	}
}

type CommandTestData struct {
	Spec  *EventContent
	Tests []*CommandTestUnit
}

type CommandTestUnit struct {
	Name   string          `json:"name"`
	Input  string          `json:"input"`
	Broken string          `json:"broken,omitempty"`
	Error  bool            `json:"error"`
	Output json.RawMessage `json:"output"`
}

func compactJSON(input json.RawMessage) json.RawMessage {
	var buf bytes.Buffer
	exerrors.PanicIfNotNil(json.Compact(&buf, input))
	return buf.Bytes()
}

func TestMSC4391BotCommandEventContent_ParseInput(t *testing.T) {
	for _, cmd := range exerrors.Must(testdata.FS.ReadDir("commands")) {
		t.Run(strings.TrimSuffix(cmd.Name(), ".json"), func(t *testing.T) {
			ctd := loadFile[CommandTestData]("commands/" + cmd.Name())
			for _, test := range ctd.Tests {
				outputStr := exbytes.UnsafeString(compactJSON(test.Output))
				t.Run(test.Name, func(t *testing.T) {
					if test.Broken != "" {
						t.Skip(test.Broken)
					}
					output, err := ctd.Spec.ParseInput("@testbot", []string{"/"}, test.Input)
					if test.Error {
						assert.Error(t, err)
					} else {
						assert.NoError(t, err)
					}
					if outputStr == "null" {
						assert.Nil(t, output)
					} else {
						assert.Equal(t, ctd.Spec.Command, output.MSC4391BotCommand.Command)
						assert.Equalf(t, outputStr, exbytes.UnsafeString(output.MSC4391BotCommand.Arguments), "Input: %s", test.Input)
					}
				})
			}
		})
	}
}
