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

func must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

func testPublishPayload() map[string]any {
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

func activateTestAppServiceStream(t *testing.T, sender *mautrix.BeeperStreamSender) *mautrix.BeeperStream {
	t.Helper()
	desc := must(sender.PrepareStream(context.Background(), "!room:example.com", "com.beeper.llm"))
	return must(desc.Activate(context.Background(), "$event"))
}

func deliverTestBotSubscribe(as *AppService, deviceID id.DeviceID) {
	as.handleEvents(context.Background(), []*event.Event{{
		Sender:     "@alice:example.com",
		ToUserID:   as.BotMXID(),
		ToDeviceID: deviceID,
		Type:       event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
			RoomID:   "!room:example.com",
			EventID:  "$event",
			DeviceID: "SUBDEVICE",
			ExpiryMS: 60_000,
		}},
	}}, event.ToDeviceEventType)
}

func TestBotClientBeeperStreamInterception(t *testing.T) {
	ts, sendToDeviceCalls := newTestBotHomeserver(t)
	as := newTestAppService(t, ts.URL)
	client := as.BotClient()
	sender := client.GetOrCreateBeeperStreamSender(&mautrix.BeeperStreamSenderOptions{
		AuthorizeSubscriber: func(context.Context, *mautrix.BeeperStreamSubscribeRequest) bool { return true },
	})
	stream := activateTestAppServiceStream(t, sender)

	deliverTestBotSubscribe(as, "*")

	require.NoError(t, stream.Publish(context.Background(), testPublishPayload()))
	require.EqualValues(t, 1, sendToDeviceCalls.Load())
	select {
	case <-as.ToDeviceEvents:
		t.Fatal("expected intercepted to-device event to not be enqueued")
	default:
	}
}

