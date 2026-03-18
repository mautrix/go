// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	testBotRoomID     = "!room:example.com"
	testBotEventID    = "$event"
	testBotStreamType = "com.beeper.llm"
	testBotSubscriber = "@alice:example.com"
	testBotSubDevice  = "SUBDEVICE"
)

func newTestPublishPayload() map[string]any {
	return map[string]any{
		"com.beeper.llm.deltas": []map[string]any{{"delta": "hello"}},
	}
}

func newTestAppService(t *testing.T, homeserverURL string) *AppService {
	t.Helper()
	as := Create()
	as.HomeserverDomain = "example.com"
	as.Registration = &Registration{
		AppToken:        "app-token",
		SenderLocalpart: "bot",
	}
	if homeserverURL != "" {
		require.NoError(t, as.SetHomeserverURL(homeserverURL))
	}
	return as
}

func newTestBotHomeserver(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var sendToDeviceCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/sendToDevice/"):
			sendToDeviceCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			t.Fatalf("unexpected homeserver request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, &sendToDeviceCalls
}

func activateTestAppServiceStream(t *testing.T, streams *mautrix.BeeperStreamManager) {
	t.Helper()
	descriptor, err := streams.NewDescriptor(context.Background(), testBotRoomID, testBotStreamType)
	require.NoError(t, err)
	require.NoError(t, streams.Register(context.Background(), testBotRoomID, testBotEventID, descriptor))
}

func deliverTestBotSubscribe(t *testing.T, as *AppService, deviceID id.DeviceID) {
	t.Helper()
	as.handleEvents(context.Background(), []*event.Event{{
		Sender:     testBotSubscriber,
		ToUserID:   as.BotMXID(),
		ToDeviceID: deviceID,
		Type:       event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
			RoomID:   testBotRoomID,
			EventID:  testBotEventID,
			DeviceID: testBotSubDevice,
			ExpiryMS: 60_000,
		}},
	}}, event.ToDeviceEventType)
}

func TestBotClientBeeperStreamInterception(t *testing.T) {
	ts, sendToDeviceCalls := newTestBotHomeserver(t)
	as := newTestAppService(t, ts.URL)
	client := as.BotClient()
	streams := client.BeeperStreams()
	streams.SetAuthorizeSubscriber(func(context.Context, *mautrix.BeeperStreamSubscribeRequest) bool { return true })
	activateTestAppServiceStream(t, streams)

	deliverTestBotSubscribe(t, as, client.DeviceID)

	require.NoError(t, streams.Publish(context.Background(), testBotRoomID, testBotEventID, newTestPublishPayload()))
	require.Equal(t, int32(1), sendToDeviceCalls.Load())
	select {
	case <-as.ToDeviceEvents:
		t.Fatal("expected intercepted to-device event to not be enqueued")
	default:
	}
}
