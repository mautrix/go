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
	"time"

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
	subscribeHandled := make(chan struct{}, 1)
	streams.SetAuthorizeSubscriber(func(context.Context, *mautrix.BeeperStreamSubscribeRequest) bool {
		select {
		case subscribeHandled <- struct{}{}:
		default:
		}
		return true
	})
	ep := NewEventProcessor(as)
	ep.ExecMode = Sync
	ep.PrependHandler(event.ToDeviceBeeperStreamSubscribe, func(ctx context.Context, evt *event.Event) {
		_, _ = client.PreDispatchToDeviceEvent(ctx, evt)
	})
	ep.PrependHandler(event.ToDeviceBeeperStreamEncrypted, func(ctx context.Context, evt *event.Event) {
		handled, keep := client.PreDispatchToDeviceEvent(ctx, evt)
		if !keep || handled || evt.Type != event.ToDeviceBeeperStreamUpdate {
			return
		}
		ep.Dispatch(ctx, evt)
	})
	ep.Start(context.Background())
	defer ep.Stop()
	activateTestAppServiceStream(t, streams)

	deliverTestBotSubscribe(t, as, client.DeviceID)
	require.Eventually(t, func() bool {
		select {
		case <-subscribeHandled:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	require.NoError(t, streams.Publish(context.Background(), testBotRoomID, testBotEventID, newTestPublishPayload()))
	require.Eventually(t, func() bool {
		return sendToDeviceCalls.Load() == 1
	}, time.Second, 10*time.Millisecond)
	select {
	case <-as.ToDeviceEvents:
		t.Fatal("expected to-device event to be consumed from appservice queue")
	default:
	}
}

func TestBotClientDropsMalformedToDeviceEvent(t *testing.T) {
	as := newTestAppService(t, "")

	as.handleEvents(context.Background(), []*event.Event{{
		Sender:     testBotSubscriber,
		ToUserID:   as.BotMXID(),
		ToDeviceID: testBotSubDevice,
		Type:       event.ToDeviceBeeperStreamSubscribe,
		Content:    event.Content{VeryRaw: json.RawMessage(`{`)},
	}}, event.ToDeviceEventType)

	select {
	case <-as.ToDeviceEvents:
		t.Fatal("expected malformed to-device event to be dropped")
	default:
	}
}
