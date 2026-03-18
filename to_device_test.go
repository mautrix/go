// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	mautrix "maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

func TestFilterSyncToDeviceEventsDropsMalformedEvents(t *testing.T) {
	var called bool
	events := []*event.Event{{
		Type:    event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{VeryRaw: json.RawMessage(`{`)},
	}}

	filtered := mautrix.FilterSyncToDeviceEvents(context.Background(), events, func(context.Context, *event.Event) (bool, bool) {
		called = true
		return true, true
	})

	require.False(t, called)
	require.Empty(t, filtered)
}

func TestFilterSyncToDeviceEventsKeepsUnsupportedEvents(t *testing.T) {
	var called bool
	events := []*event.Event{{
		Type:    event.Type{Type: "com.example.unsupported", Class: event.ToDeviceEventType},
		Content: event.Content{VeryRaw: json.RawMessage(`{"foo":"bar"}`)},
	}}

	filtered := mautrix.FilterSyncToDeviceEvents(context.Background(), events, func(context.Context, *event.Event) (bool, bool) {
		called = true
		return true, true
	})

	require.False(t, called)
	require.Len(t, filtered, 1)
	require.Nil(t, filtered[0].Content.Parsed)
}
