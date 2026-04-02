package mautrix_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type capturedRequest struct {
	method string
	path   string
	body   map[string]any
}

func newCapturedClient(t *testing.T, versions *mautrix.RespVersions) (*mautrix.Client, *capturedRequest) {
	t.Helper()
	captured := &capturedRequest{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &captured.body))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	client, err := mautrix.NewClient(ts.URL, "@alice:example.com", "token")
	require.NoError(t, err)
	client.SpecVersions = versions
	return client, captured
}

func TestSetReadMarkers_AllowBackwardIncludedWhenSupported(t *testing.T) {
	client, captured := newCapturedClient(t, &mautrix.RespVersions{
		UnstableFeatures: map[string]bool{"com.beeper.msc4446": true},
	})
	err := client.SetReadMarkers(context.Background(), id.RoomID("!room:example.com"), &mautrix.ReqSetReadMarkers{
		FullyRead:           id.EventID("$event"),
		BeeperAllowBackward: true,
	})
	require.NoError(t, err)
	require.Equal(t, http.MethodPost, captured.method)
	require.Equal(t, "/_matrix/client/v3/rooms/!room:example.com/read_markers", captured.path)
	require.Equal(t, "$event", captured.body["m.fully_read"])
	require.Equal(t, true, captured.body["com.beeper.allow_backward"])
}

func TestSetReadMarkers_AllowBackwardOmittedWhenUnsupported(t *testing.T) {
	client, captured := newCapturedClient(t, &mautrix.RespVersions{UnstableFeatures: map[string]bool{}})
	err := client.SetReadMarkers(context.Background(), id.RoomID("!room:example.com"), &mautrix.ReqSetReadMarkers{
		FullyRead:           id.EventID("$event"),
		BeeperAllowBackward: true,
	})
	require.NoError(t, err)
	require.NotContains(t, captured.body, "com.beeper.allow_backward")
	clientNoVersions, capturedNoVersions := newCapturedClient(t, nil)
	err = clientNoVersions.SetReadMarkers(context.Background(), id.RoomID("!room:example.com"), &mautrix.ReqSetReadMarkers{
		FullyRead:           id.EventID("$event"),
		BeeperAllowBackward: true,
	})
	require.NoError(t, err)
	require.NotContains(t, capturedNoVersions.body, "com.beeper.allow_backward")
}

func TestSendReceipt_AllowBackwardIncludedOnlyForFullyReadWhenSupported(t *testing.T) {
	client, captured := newCapturedClient(t, &mautrix.RespVersions{
		UnstableFeatures: map[string]bool{"com.beeper.msc4446": true},
	})
	err := client.SendReceipt(context.Background(), id.RoomID("!room:example.com"), id.EventID("$event"), event.ReceiptType("m.fully_read"), &mautrix.ReqSendReceipt{
		BeeperAllowBackward: true,
	})
	require.NoError(t, err)
	require.Equal(t, "/_matrix/client/v3/rooms/!room:example.com/receipt/m.fully_read/$event", captured.path)
	require.Equal(t, true, captured.body["com.beeper.allow_backward"])
	client2, captured2 := newCapturedClient(t, &mautrix.RespVersions{
		UnstableFeatures: map[string]bool{"com.beeper.msc4446": true},
	})
	err = client2.SendReceipt(context.Background(), id.RoomID("!room:example.com"), id.EventID("$event"), event.ReceiptTypeRead, &mautrix.ReqSendReceipt{
		BeeperAllowBackward: true,
	})
	require.NoError(t, err)
	require.NotContains(t, captured2.body, "com.beeper.allow_backward")
}

func TestSendReceipt_AllowBackwardOmittedWhenUnsupported(t *testing.T) {
	client, captured := newCapturedClient(t, &mautrix.RespVersions{UnstableFeatures: map[string]bool{}})
	err := client.SendReceipt(context.Background(), id.RoomID("!room:example.com"), id.EventID("$event"), event.ReceiptType("m.fully_read"), &mautrix.ReqSendReceipt{
		BeeperAllowBackward: true,
	})
	require.NoError(t, err)
	require.NotContains(t, captured.body, "com.beeper.allow_backward")
}
