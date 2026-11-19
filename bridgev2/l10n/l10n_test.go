// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package l10n_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/bridgev2/l10n"
)

var (
	testNS          = l10n.NewNamespace("l10n-test")
	tplSimple       = testNS.Define("simple", "Scan the QR code")
	tplParams       = testNS.Define("params", "Logged in as {name} on {device}", l10n.WithComment("name is a phone number"))
	tplPlural       = testNS.DefinePlural("plural", "count", "You have one device", "You have {count} devices")
	tplPluralNoBody = testNS.DefinePlural("plural_no_body", "n", "Item", "Items")
)

func TestRender(t *testing.T) {
	assert.Equal(t, l10n.Message{Key: "l10n-test:simple", Text: "Scan the QR code"}, tplSimple.Message())
	assert.Equal(t, l10n.Message{
		Key:    "l10n-test:params",
		Text:   "Logged in as +1555 on Chrome",
		Params: l10n.Params{"name": "+1555", "device": "Chrome"},
	}, tplParams.Render(l10n.Params{"name": "+1555", "device": "Chrome"}))
	assert.Equal(t, "You have one device", tplPlural.Render(l10n.Params{"count": 1}).Text)
	msg := tplPlural.Render(l10n.Params{"count": 3})
	assert.Equal(t, "You have 3 devices", msg.Text)
	assert.Equal(t, int64(3), msg.Params["count"])
	assert.Equal(t, "Items", tplPluralNoBody.Render(l10n.Params{"n": 0}).Text)
}

func TestRenderInvalidParams(t *testing.T) {
	orig := l10n.RenderErrorHandler
	defer func() { l10n.RenderErrorHandler = orig }()
	var gotErr error
	l10n.RenderErrorHandler = func(_ *l10n.Template, err error) { gotErr = err }

	msg := tplParams.Render(l10n.Params{"name": "+1555", "extra": "x"})
	assert.Equal(t, l10n.Unlocalized("Logged in as +1555 on {device}"), msg)
	assert.EqualError(t, gotErr, `l10n: invalid params for l10n-test:params: missing param "device", unknown param "extra"`)

	gotErr = nil
	msg = tplPlural.Render(l10n.Params{"count": "3"})
	assert.False(t, msg.IsLocalizable())
	assert.Error(t, gotErr)

	gotErr = nil
	msg = tplParams.Render(l10n.Params{"name": 1.5, "device": "x"})
	assert.Equal(t, "Logged in as 1.5 on x", msg.Text)
	assert.Error(t, gotErr)
}

func TestDuplicateKeyPanics(t *testing.T) {
	assert.Panics(t, func() { testNS.Define("simple", "Again") })
	assert.Panics(t, func() { testNS.Define("Not Valid", "x") })
	assert.Panics(t, func() { l10n.NewNamespace("Bad Namespace") })
}

func TestJSON(t *testing.T) {
	msg := tplParams.Render(l10n.Params{"name": "+1555", "device": "Chrome"})
	data, err := json.Marshal(msg)
	require.NoError(t, err)
	assert.JSONEq(t, `{"key":"l10n-test:params","text":"Logged in as +1555 on Chrome","params":{"name":"+1555","device":"Chrome"}}`, string(data))

	var parsed l10n.Message
	require.NoError(t, json.Unmarshal(data, &parsed))
	assert.Equal(t, msg, parsed)

	require.NoError(t, json.Unmarshal([]byte(`{"key":"l10n-test:plural","text":"You have 3 devices","params":{"count":3}}`), &parsed))
	assert.Equal(t, int64(3), parsed.Params["count"])

	require.NoError(t, json.Unmarshal([]byte(`"plain old string"`), &parsed))
	assert.Equal(t, l10n.Unlocalized("plain old string"), parsed)

	err = json.Unmarshal([]byte(`{"text":"x","params":{"bad":1.5}}`), &parsed)
	assert.Error(t, err)
}

func TestCatalog(t *testing.T) {
	entries := l10n.Catalog("l10n-test")
	require.Len(t, entries, 4)
	assert.Equal(t, l10n.CatalogEntry{
		Key:     "l10n-test:params",
		English: "Logged in as {name} on {device}",
		Params:  []string{"device", "name"},
		Comment: "name is a phone number",
	}, entries[0])
	assert.Equal(t, l10n.CatalogEntry{
		Key:         "l10n-test:plural",
		English:     "You have {count} devices",
		EnglishOne:  "You have one device",
		PluralParam: "count",
		Params:      []string{"count"},
	}, entries[1])
}
