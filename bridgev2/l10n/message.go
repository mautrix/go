// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package l10n contains the localizable message type used for user-facing
// strings that bridges send to clients.
//
// A Message always carries fully rendered English text, so clients that don't
// localize can display it as-is. When the message was rendered from a
// Template, it also carries the template key and the parameters that were
// substituted into it, which lets a client look up its own translation of the
// key and render it with the same parameters.
package l10n

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/rs/zerolog"
)

// Params are the values substituted into a template. Values must be strings or
// integers; Template.Render normalizes integers to int64.
type Params map[string]any

// Message is a user-facing string.
type Message struct {
	// Key identifies the template this message was rendered from, in the form
	// "<namespace>:<id>". Empty means the message is not localizable.
	Key string `json:"key,omitempty"`
	// Text is the fully rendered English text. It is always safe to display.
	Text string `json:"text"`
	// Params are the values that were substituted into the template to produce
	// Text. Clients need them to render a translation of Key.
	Params Params `json:"params,omitempty"`
}

// Unlocalized wraps text that can't be localized, such as strings coming from
// the remote network.
func Unlocalized(text string) Message {
	return Message{Text: text}
}

func (m Message) String() string {
	return m.Text
}

func (m Message) IsZero() bool {
	return m.Key == "" && m.Text == "" && len(m.Params) == 0
}

func (m Message) IsLocalizable() bool {
	return m.Key != ""
}

func (m Message) MarshalZerologObject(e *zerolog.Event) {
	e.Str("text", m.Text)
	if m.Key != "" {
		e.Str("key", m.Key)
	}
}

// UnmarshalJSON accepts both the object form and a bare JSON string. A bare
// string becomes an unlocalized message, which is how text from older bridges
// and older events is read.
func (m *Message) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '"' {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
		*m = Unlocalized(text)
		return nil
	} else if bytes.Equal(data, []byte("null")) {
		return nil
	}
	var raw struct {
		Key    string                     `json:"key"`
		Text   string                     `json:"text"`
		Params map[string]json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*m = Message{Key: raw.Key, Text: raw.Text}
	if len(raw.Params) > 0 {
		m.Params = make(Params, len(raw.Params))
		for name, val := range raw.Params {
			parsed, err := parseParamValue(val)
			if err != nil {
				return fmt.Errorf("invalid value for param %q: %w", name, err)
			}
			m.Params[name] = parsed
		}
	}
	return nil
}

func parseParamValue(raw json.RawMessage) (any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' {
		var str string
		err := json.Unmarshal(raw, &str)
		return str, err
	}
	val, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("must be a string or an integer")
	}
	return val, nil
}
