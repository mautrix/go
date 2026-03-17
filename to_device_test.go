package mautrix

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/event"
)

func TestFilterSyncToDeviceEventsDropsMalformedEvents(t *testing.T) {
	var called bool
	events := []*event.Event{{
		Type:    event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{VeryRaw: json.RawMessage(`{`)},
	}}

	filtered := FilterSyncToDeviceEvents(context.Background(), events, func(context.Context, *event.Event) bool {
		called = true
		return true
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

	filtered := FilterSyncToDeviceEvents(context.Background(), events, func(context.Context, *event.Event) bool {
		called = true
		return true
	})

	require.False(t, called)
	require.Len(t, filtered, 1)
	require.Nil(t, filtered[0].Content.Parsed)
}
