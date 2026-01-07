// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/event/botcommandtestdata"
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

func TestParseQuoted(t *testing.T) {
	var qptd []QuoteParseTestData
	dec := json.NewDecoder(exerrors.Must(botcommandtestdata.FS.Open("parse_quote.json")))
	exerrors.PanicIfNotNil(dec.Decode(&qptd))
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
