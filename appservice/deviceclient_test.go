package appservice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func newTestAppService(t *testing.T, homeserverURL string) *AppService {
	t.Helper()
	as := Create()
	as.HomeserverDomain = "example.com"
	as.Registration = &Registration{
		AppToken:        "app-token",
		SenderLocalpart: "bot",
	}
	if homeserverURL != "" {
		if err := as.SetHomeserverURL(homeserverURL); err != nil {
			t.Fatalf("failed to set homeserver URL: %v", err)
		}
	}
	return as
}

func TestGetOrCreateBotDeviceClientUsesStoredDeviceID(t *testing.T) {
	var loginCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginCalls.Add(1)
		t.Fatalf("unexpected homeserver request: %s %s", r.Method, r.URL.Path)
	}))
	defer ts.Close()

	as := newTestAppService(t, ts.URL)
	var savedDeviceID id.DeviceID
	client, err := as.GetOrCreateBotDeviceClient(context.Background(), BotDeviceClientOptions{
		Purpose:                  "stream",
		InitialDeviceDisplayName: "Stream Bot",
		LoadDeviceID: func(context.Context) (id.DeviceID, error) {
			return "STOREDDEVICE", nil
		},
		SaveDeviceID: func(_ context.Context, deviceID id.DeviceID) error {
			savedDeviceID = deviceID
			return nil
		},
	})
	if err != nil {
		t.Fatalf("GetOrCreateBotDeviceClient returned error: %v", err)
	}
	if client.DeviceID != "STOREDDEVICE" {
		t.Fatalf("unexpected device ID %q", client.DeviceID)
	}
	if !client.SetAppServiceDeviceID {
		t.Fatal("expected SetAppServiceDeviceID to be enabled for stored device reuse")
	}
	if savedDeviceID != "STOREDDEVICE" {
		t.Fatalf("expected stored device ID to be persisted, got %q", savedDeviceID)
	}
	if loginCalls.Load() != 0 {
		t.Fatalf("expected no homeserver requests, got %d", loginCalls.Load())
	}
}

func TestGetOrCreateBotDeviceClientProvisioningAndInterception(t *testing.T) {
	var loginCalls atomic.Int32
	var sendToDeviceCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/_matrix/client/v3/login":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"flows": []map[string]any{{"type": string(mautrix.AuthTypeAppservice)}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/_matrix/client/v3/login":
			loginCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":      "@bot:example.com",
				"device_id":    "NEWDEVICE",
				"access_token": "device-access-token",
			})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/sendToDevice/"):
			sendToDeviceCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			t.Fatalf("unexpected homeserver request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	as := newTestAppService(t, ts.URL)
	var savedDeviceID id.DeviceID
	client, err := as.GetOrCreateBotDeviceClient(context.Background(), BotDeviceClientOptions{
		Purpose:                  "stream",
		InitialDeviceDisplayName: "Stream Bot",
		SaveDeviceID: func(_ context.Context, deviceID id.DeviceID) error {
			savedDeviceID = deviceID
			return nil
		},
	})
	if err != nil {
		t.Fatalf("GetOrCreateBotDeviceClient returned error: %v", err)
	}
	if client.DeviceID != "NEWDEVICE" {
		t.Fatalf("unexpected device ID %q", client.DeviceID)
	}
	if savedDeviceID != "NEWDEVICE" {
		t.Fatalf("expected saved device ID NEWDEVICE, got %q", savedDeviceID)
	}
	if loginCalls.Load() != 1 {
		t.Fatalf("expected one login call, got %d", loginCalls.Load())
	}

	cachedClient, err := as.GetOrCreateBotDeviceClient(context.Background(), BotDeviceClientOptions{
		Purpose:                  "stream",
		InitialDeviceDisplayName: "Different Name",
	})
	if err != nil {
		t.Fatalf("second GetOrCreateBotDeviceClient returned error: %v", err)
	}
	if cachedClient != client {
		t.Fatal("expected second call to return cached client")
	}
	if loginCalls.Load() != 1 {
		t.Fatalf("expected cached client to avoid additional login calls, got %d", loginCalls.Load())
	}

	sender := client.GetOrCreateBeeperStreamSender(nil)
	publisher := sender.NewPublisher(&mautrix.BeeperStreamPublisherOptions{
		AuthorizeSubscriber: func(context.Context, *mautrix.BeeperStreamSubscribeRequest) bool { return true },
	})
	desc, err := publisher.PrepareStream(context.Background(), "!room:example.com", "com.beeper.llm")
	if err != nil {
		t.Fatalf("PrepareStream returned error: %v", err)
	}
	stream, err := desc.Activate(context.Background(), "$event")
	if err != nil {
		t.Fatalf("Activate returned error: %v", err)
	}

	as.handleEvents(context.Background(), []*event.Event{{
		Sender:     "@alice:example.com",
		ToUserID:   as.BotMXID(),
		ToDeviceID: "NEWDEVICE",
		Type:       event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
			RoomID:   "!room:example.com",
			EventID:  "$event",
			DeviceID: "SUBDEVICE",
			ExpiryMS: 60_000,
		}},
	}}, event.ToDeviceEventType)

	if err = stream.Publish(context.Background(), map[string]any{
		"com.beeper.llm.deltas": []map[string]any{{"delta": "hello"}},
	}); err != nil {
		t.Fatalf("Publish returned error: %v", err)
	}
	if sendToDeviceCalls.Load() != 1 {
		t.Fatalf("expected intercepted subscriber to receive one update, got %d calls", sendToDeviceCalls.Load())
	}
	select {
	case <-as.ToDeviceEvents:
		t.Fatal("expected intercepted to-device event to not be enqueued")
	default:
	}
}

func TestNewBeeperStreamPublisherPassesOptions(t *testing.T) {
	var loginCalls atomic.Int32
	var sendToDeviceCalls atomic.Int32
	var authorizeCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/_matrix/client/v3/login":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"flows": []map[string]any{{"type": string(mautrix.AuthTypeAppservice)}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/_matrix/client/v3/login":
			loginCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":      "@bot:example.com",
				"device_id":    "NEWDEVICE",
				"access_token": "device-access-token",
			})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/sendToDevice/"):
			sendToDeviceCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			t.Fatalf("unexpected homeserver request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	as := newTestAppService(t, ts.URL)
	publisher, err := as.NewBeeperStreamPublisher(context.Background(), BotDeviceClientOptions{
		Purpose:                  "stream",
		InitialDeviceDisplayName: "Stream Bot",
	}, &mautrix.BeeperStreamPublisherOptions{
		AuthorizeSubscriber: func(context.Context, *mautrix.BeeperStreamSubscribeRequest) bool {
			authorizeCalls.Add(1)
			return false
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewBeeperStreamPublisher returned error: %v", err)
	}
	if loginCalls.Load() != 1 {
		t.Fatalf("expected one login call, got %d", loginCalls.Load())
	}

	desc, err := publisher.PrepareStream(context.Background(), "!room:example.com", "com.beeper.llm")
	if err != nil {
		t.Fatalf("PrepareStream returned error: %v", err)
	}
	stream, err := desc.Activate(context.Background(), "$event")
	if err != nil {
		t.Fatalf("Activate returned error: %v", err)
	}

	as.handleEvents(context.Background(), []*event.Event{{
		Sender:     "@alice:example.com",
		ToUserID:   as.BotMXID(),
		ToDeviceID: "NEWDEVICE",
		Type:       event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
			RoomID:   "!room:example.com",
			EventID:  "$event",
			DeviceID: "SUBDEVICE",
			ExpiryMS: 60_000,
		}},
	}}, event.ToDeviceEventType)

	if err = stream.Publish(context.Background(), map[string]any{
		"com.beeper.llm.deltas": []map[string]any{{"delta": "hello"}},
	}); err != nil {
		t.Fatalf("Publish returned error: %v", err)
	}
	if authorizeCalls.Load() != 1 {
		t.Fatalf("expected authorize callback to be called once, got %d", authorizeCalls.Load())
	}
	if sendToDeviceCalls.Load() != 0 {
		t.Fatalf("expected denied subscriber to receive no updates, got %d send calls", sendToDeviceCalls.Load())
	}
}
