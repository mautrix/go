package mautrix

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func TestBeeperStreamReceiverHandleTimelineEventSubscribes(t *testing.T) {
	requests := make(chan struct {
		path string
		body []byte
	}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected method %s", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		select {
		case requests <- struct {
			path string
			body []byte
		}{path: r.URL.Path, body: body}:
		default:
		}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, testStreamSubscriberID, "access-token")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	client.DeviceID = testStreamSubscriberDev
	receiver := client.GetOrCreateBeeperStreamReceiver(&BeeperStreamReceiverOptions{
		DefaultExpiry:        time.Minute,
		MinimumRenewInterval: time.Hour,
	})
	desc := &event.BeeperStreamInfo{
		UserID:   testStreamBotUserID,
		DeviceID: testStreamBotDeviceID,
		Type:     testStreamType,
		ExpiryMS: 60_000,
	}

	receiver.HandleTimelineEvent(context.Background(), &event.Event{
		ID:     testStreamEventID,
		RoomID: testStreamRoomID,
		Type:   event.EventMessage,
		Content: event.Content{Parsed: &event.MessageEventContent{
			MsgType:      event.MsgText,
			Body:         "Pondering...",
			BeeperStream: desc,
		}},
	})
	defer receiver.StopSubscription(testStreamRoomID, testStreamEventID)

	select {
	case req := <-requests:
		if !strings.Contains(req.path, "/sendToDevice/com.beeper.stream.subscribe/") {
			t.Fatalf("unexpected sendToDevice path %q", req.path)
		}
		var payload struct {
			Messages map[string]map[string]json.RawMessage `json:"messages"`
		}
		if err := json.Unmarshal(req.body, &payload); err != nil {
			t.Fatalf("failed to unmarshal sendToDevice request: %v", err)
		}
		targetUser := payload.Messages[string(testStreamBotUserID)]
		rawContent := targetUser[string(testStreamBotDeviceID)]
		var subscribe event.BeeperStreamSubscribeEventContent
		if err := json.Unmarshal(rawContent, &subscribe); err != nil {
			t.Fatalf("failed to unmarshal subscribe request: %v", err)
		}
		if subscribe.RoomID != testStreamRoomID || subscribe.EventID != testStreamEventID || subscribe.DeviceID != testStreamSubscriberDev {
			t.Fatalf("unexpected subscribe payload: %#v", subscribe)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for subscribe request")
	}
}

func TestBeeperStreamReceiverStopsOnFinalEdit(t *testing.T) {
	receiver := NewBeeperStreamReceiver(&Client{
		UserID:   testStreamSubscriberID,
		DeviceID: testStreamSubscriberDev,
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	receiver.subscriptions[beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID}] = &beeperStreamSubscription{
		key:    beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID},
		cancel: cancel,
	}

	receiver.HandleTimelineEvent(context.Background(), &event.Event{
		RoomID: testStreamRoomID,
		Type:   event.EventMessage,
		Content: event.Content{Parsed: &event.MessageEventContent{
			MsgType:   event.MsgText,
			Body:      "* done",
			RelatesTo: (&event.RelatesTo{}).SetReplace(testStreamEventID),
			NewContent: &event.MessageEventContent{
				MsgType: event.MsgText,
				Body:    "done",
			},
		}},
	})

	if _, ok := receiver.subscriptions[beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID}]; ok {
		t.Fatal("expected subscription to be removed")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("expected subscription cancel to be called")
	}
}

func TestBeeperStreamReceiverPlainUpdateCallback(t *testing.T) {
	received := make(chan *BeeperStreamUpdate, 1)
	receiver := NewBeeperStreamReceiver(nil, &BeeperStreamReceiverOptions{
		OnUpdate: func(_ context.Context, update *BeeperStreamUpdate) error {
			received <- update
			return nil
		},
	})
	// Issue 1: subscription must exist and sender must match for update to be dispatched.
	receiver.subscriptions[beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID}] = &beeperStreamSubscription{
		key: beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID},
		descriptor: &event.BeeperStreamInfo{
			UserID:   testStreamBotUserID,
			DeviceID: testStreamBotDeviceID,
			Type:     testStreamType,
		},
		cancel: func() {},
	}
	content, err := newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello"))
	if err != nil {
		t.Fatalf("newStreamUpdateContent returned error: %v", err)
	}

	consumed := receiver.HandleToDeviceEvent(context.Background(), &event.Event{
		Sender:  testStreamBotUserID,
		Type:    event.ToDeviceBeeperStreamUpdate,
		Content: *content,
	})
	if !consumed {
		t.Fatal("expected plain update to be consumed")
	}

	select {
	case update := <-received:
		if update.Sender != testStreamBotUserID || update.RoomID != testStreamRoomID || update.EventID != testStreamEventID {
			t.Fatalf("unexpected update metadata: %#v", update)
		}
		assertStreamUpdateMap(t, decodeJSONMap(t, mustMarshalJSON(t, update.Content)))
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for update callback")
	}
}

func TestBeeperStreamReceiverEncryptedUpdateCallback(t *testing.T) {
	received := make(chan *BeeperStreamUpdate, 1)
	receiver := NewBeeperStreamReceiver(nil, &BeeperStreamReceiverOptions{
		OnUpdate: func(_ context.Context, update *BeeperStreamUpdate) error {
			received <- update
			return nil
		},
	})
	encKey := makeStreamKey()
	streamID := makeStreamID()
	sub := &beeperStreamSubscription{
		key: beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID},
		descriptor: &event.BeeperStreamInfo{
			UserID:   testStreamBotUserID,
			DeviceID: testStreamBotDeviceID,
			Type:     testStreamType,
			Encryption: &event.BeeperStreamEncryptionInfo{
				Algorithm: id.AlgorithmBeeperStreamAESGCM,
				Key:       encKey,
				StreamID:  streamID,
			},
		},
		cancel: func() {},
	}
	receiver.subscriptions[sub.key] = sub
	receiver.subscriptionsByStreamID[streamID] = sub
	content, err := newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello"))
	if err != nil {
		t.Fatalf("newStreamUpdateContent returned error: %v", err)
	}
	encrypted, err := EncryptBeeperStreamEvent(event.ToDeviceBeeperStreamUpdate, content, streamID, encKey)
	if err != nil {
		t.Fatalf("EncryptBeeperStreamEvent returned error: %v", err)
	}

	consumed := receiver.HandleToDeviceEvent(context.Background(), &event.Event{
		Sender:  testStreamBotUserID,
		Type:    event.ToDeviceEncrypted,
		Content: event.Content{Parsed: encrypted},
	})
	if !consumed {
		t.Fatal("expected encrypted update to be consumed")
	}

	select {
	case update := <-received:
		if update.Sender != testStreamBotUserID || update.RoomID != testStreamRoomID || update.EventID != testStreamEventID {
			t.Fatalf("unexpected update metadata: %#v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for encrypted update callback")
	}
}

func TestBeeperStreamReceiverEncryptedUpdateIgnoresWrongRoute(t *testing.T) {
	var called bool
	receiver := NewBeeperStreamReceiver(nil, &BeeperStreamReceiverOptions{
		OnUpdate: func(_ context.Context, update *BeeperStreamUpdate) error {
			called = true
			return nil
		},
	})
	encKey := makeStreamKey()
	streamID := makeStreamID()
	sub := &beeperStreamSubscription{
		key: beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID},
		descriptor: &event.BeeperStreamInfo{
			UserID:   testStreamBotUserID,
			DeviceID: testStreamBotDeviceID,
			Type:     testStreamType,
			Encryption: &event.BeeperStreamEncryptionInfo{
				Algorithm: id.AlgorithmBeeperStreamAESGCM,
				Key:       encKey,
				StreamID:  streamID,
			},
		},
		cancel: func() {},
	}
	receiver.subscriptions[sub.key] = sub
	receiver.subscriptionsByStreamID[streamID] = sub
	content, err := newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello"))
	if err != nil {
		t.Fatalf("newStreamUpdateContent returned error: %v", err)
	}
	// Encrypt with a different stream_id — the receiver should not find a matching subscription.
	encrypted, err := EncryptBeeperStreamEvent(event.ToDeviceBeeperStreamUpdate, content, makeStreamID(), encKey)
	if err != nil {
		t.Fatalf("EncryptBeeperStreamEvent returned error: %v", err)
	}

	consumed := receiver.HandleToDeviceEvent(context.Background(), &event.Event{
		Sender:  testStreamBotUserID,
		Type:    event.ToDeviceEncrypted,
		Content: event.Content{Parsed: encrypted},
	})
	if !consumed {
		t.Fatal("expected encrypted update to be consumed")
	}
	if called {
		t.Fatal("expected mismatched encrypted update to be ignored")
	}
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	return data
}
