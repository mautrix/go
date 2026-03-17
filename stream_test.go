package mautrix

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	testStreamRoomID        id.RoomID   = "!room:example.com"
	testStreamEventID       id.EventID  = "$event"
	testStreamType                      = "com.beeper.llm"
	testStreamBotUserID     id.UserID   = "@bot:example.com"
	testStreamBotDeviceID   id.DeviceID = "BOTDEVICE"
	testStreamSubscriberID  id.UserID   = "@alice:example.com"
	testStreamSubscriberDev id.DeviceID = "SUBDEVICE"
	testStreamDeltaKey                  = "com.beeper.llm.deltas"
)

func newTestStreamSender(encrypted bool) *BeeperStreamSender {
	opts := &BeeperStreamSenderOptions{}
	if encrypted {
		opts.IsEncrypted = func(context.Context, id.RoomID) (bool, error) { return true, nil }
	}
	return NewBeeperStreamSender(&Client{
		UserID:     testStreamBotUserID,
		DeviceID:   testStreamBotDeviceID,
		StateStore: NewMemoryStateStore(),
	}, opts)
}

func newTestStreamPublisher(t *testing.T, encrypted bool, authorize func(context.Context, *BeeperStreamSubscribeRequest) bool) (*BeeperStreamSender, *BeeperStreamPublisher, *BeeperStreamDescriptor) {
	t.Helper()
	sender := newTestStreamSender(encrypted)
	publisher := sender.NewPublisher(&BeeperStreamPublisherOptions{AuthorizeSubscriber: authorize})
	desc, err := publisher.PrepareStream(context.Background(), testStreamRoomID, testStreamType)
	if err != nil {
		t.Fatalf("PrepareStream returned error: %v", err)
	}
	return sender, publisher, desc
}

func startTestStream(t *testing.T, desc *BeeperStreamDescriptor) *BeeperStream {
	t.Helper()
	stream, err := desc.Activate(context.Background(), testStreamEventID)
	if err != nil {
		t.Fatalf("Activate returned error: %v", err)
	}
	return stream
}

func newTestPublishContent(delta string) map[string]any {
	return map[string]any{
		testStreamDeltaKey: []map[string]any{{"delta": delta}},
	}
}

func newTestSubscribeContent() *event.Content {
	return &event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
		RoomID:   testStreamRoomID,
		EventID:  testStreamEventID,
		DeviceID: testStreamSubscriberDev,
		ExpiryMS: 60_000,
	}}
}

func newTestSubscribeEvent(t *testing.T, desc *event.BeeperStreamInfo, toUserID id.UserID, toDeviceID id.DeviceID) *event.Event {
	t.Helper()
	content := newTestSubscribeContent()
	if desc != nil && desc.Encryption != nil {
		gcm, err := newStreamGCM(desc.Encryption.Key)
		if err != nil {
			t.Fatalf("newStreamGCM returned error: %v", err)
		}
		encrypted, err := encryptStreamPayload(event.ToDeviceBeeperStreamSubscribe, content, desc.Encryption.StreamID, gcm)
		if err != nil {
			t.Fatalf("encryptStreamPayload returned error: %v", err)
		}
		return &event.Event{
			Sender:  testStreamSubscriberID,
			Type:    event.ToDeviceEncrypted,
			Content: event.Content{Parsed: encrypted},
		}
	}
	return &event.Event{
		Sender:     testStreamSubscriberID,
		ToUserID:   toUserID,
		ToDeviceID: toDeviceID,
		Type:       event.ToDeviceBeeperStreamSubscribe,
		Content:    *content,
	}
}

func decodeJSONMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON map: %v", err)
	}
	return parsed
}

func assertStreamUpdateMap(t *testing.T, parsed map[string]any) {
	t.Helper()
	if parsed["room_id"] != string(testStreamRoomID) {
		t.Fatalf("unexpected room_id: %#v", parsed["room_id"])
	}
	if parsed["event_id"] != string(testStreamEventID) {
		t.Fatalf("unexpected event_id: %#v", parsed["event_id"])
	}
	if _, ok := parsed["type"]; ok {
		t.Fatalf("unexpected type field: %#v", parsed["type"])
	}
	if _, ok := parsed["content"]; ok {
		t.Fatalf("unexpected nested content field: %#v", parsed["content"])
	}
	if _, ok := parsed[testStreamDeltaKey]; !ok {
		t.Fatalf("missing %s in content: %#v", testStreamDeltaKey, parsed)
	}
}

func requireTestStreamState(t *testing.T, sender *BeeperStreamSender) *beeperStreamState {
	t.Helper()
	state := sender.streams[beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID}]
	if state == nil {
		t.Fatal("expected stream state to exist")
	}
	return state
}

func TestNewStreamUpdateContentMarshal(t *testing.T) {
	content, err := newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello"))
	if err != nil {
		t.Fatalf("newStreamUpdateContent returned error: %v", err)
	}

	data, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("failed to marshal update content: %v", err)
	}
	assertStreamUpdateMap(t, decodeJSONMap(t, data))
}

func TestNewStreamUpdateContentRejectsReservedKeys(t *testing.T) {
	for _, key := range []string{"room_id", "event_id"} {
		t.Run(key, func(t *testing.T) {
			content := newTestPublishContent("hello")
			content[key] = "override"
			if _, err := newStreamUpdateContent(testStreamRoomID, testStreamEventID, content); err == nil {
				t.Fatalf("expected %s override to be rejected", key)
			}
		})
	}
}

func TestEncryptDecryptStreamPayloadRoundTrip(t *testing.T) {
	key := makeStreamKey()
	content, err := newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello"))
	if err != nil {
		t.Fatalf("newStreamUpdateContent returned error: %v", err)
	}

	gcm, err := newStreamGCM(key)
	if err != nil {
		t.Fatalf("newStreamGCM returned error: %v", err)
	}

	streamID := makeStreamID()
	encrypted, err := encryptStreamPayload(event.ToDeviceBeeperStreamUpdate, content, streamID, gcm)
	if err != nil {
		t.Fatalf("encryptStreamPayload returned error: %v", err)
	}
	if encrypted.Algorithm != id.AlgorithmBeeperStreamAESGCM {
		t.Fatalf("unexpected algorithm: %q", encrypted.Algorithm)
	}
	if encrypted.IV == "" || len(encrypted.StreamCiphertext) == 0 {
		t.Fatalf("encrypted payload missing IV or ciphertext: %#v", encrypted)
	}
	if encrypted.StreamID != streamID {
		t.Fatalf("encrypted payload missing stream ID: %#v", encrypted)
	}

	decrypted, err := decryptStreamPayload(encrypted, gcm)
	if err != nil {
		t.Fatalf("decryptStreamPayload returned error: %v", err)
	}
	if decrypted.Type != event.ToDeviceBeeperStreamUpdate.Type {
		t.Fatalf("unexpected decrypted type: %q", decrypted.Type)
	}
	assertStreamUpdateMap(t, decodeJSONMap(t, decrypted.Content))
}

func TestHandlePlainSubscribe(t *testing.T) {
	var gotAuth *BeeperStreamSubscribeRequest
	sender, _, desc := newTestStreamPublisher(t, false, func(_ context.Context, req *BeeperStreamSubscribeRequest) bool {
		gotAuth = req
		return req.UserID == testStreamSubscriberID
	})
	startTestStream(t, desc)

	if !sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, nil, "", "")) {
		t.Fatal("expected plain subscribe to be consumed")
	}

	state := requireTestStreamState(t, sender)
	if len(state.subscribers) != 1 {
		t.Fatalf("expected 1 subscriber, got %d", len(state.subscribers))
	}
	if gotAuth == nil {
		t.Fatal("expected authorize callback to be invoked")
	}
	if gotAuth.RoomID != testStreamRoomID || gotAuth.EventID != testStreamEventID || gotAuth.UserID != testStreamSubscriberID || gotAuth.DeviceID != testStreamSubscriberDev {
		t.Fatalf("unexpected authorize callback request: %#v", gotAuth)
	}
}

func TestPendingSubscribeReplay(t *testing.T) {
	for _, tc := range []struct {
		name      string
		encrypted bool
	}{
		{name: "plain", encrypted: false},
		{name: "encrypted", encrypted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender, _, desc := newTestStreamPublisher(t, tc.encrypted, func(context.Context, *BeeperStreamSubscribeRequest) bool {
				return true
			})

			if !sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, desc.Info, "", "")) {
				t.Fatalf("expected %s subscribe to be consumed", tc.name)
			}
			if len(sender.pendingSubscribe) != 1 {
				t.Fatalf("expected 1 pending subscribe, got %d", len(sender.pendingSubscribe))
			}

			startTestStream(t, desc)

			if len(sender.pendingSubscribe) != 0 {
				t.Fatalf("expected pending subscribes to be replayed, got %d left", len(sender.pendingSubscribe))
			}
			state := requireTestStreamState(t, sender)
			if len(state.subscribers) != 1 {
				t.Fatalf("expected 1 replayed subscriber, got %d", len(state.subscribers))
			}
		})
	}
}

func TestStreamPublishAndFinishWithDirectClient(t *testing.T) {
	var sendPath string
	var sendBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected method %s", r.Method)
		}
		sendPath = r.URL.Path
		var err error
		sendBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, testStreamBotUserID, "access-token")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	client.DeviceID = testStreamBotDeviceID
	client.StateStore = NewMemoryStateStore()

	sender := client.GetOrCreateBeeperStreamSender(nil)
	publisher := sender.NewPublisher(&BeeperStreamPublisherOptions{
		AuthorizeSubscriber: func(context.Context, *BeeperStreamSubscribeRequest) bool { return true },
	})
	desc, err := publisher.PrepareStream(context.Background(), testStreamRoomID, testStreamType)
	if err != nil {
		t.Fatalf("PrepareStream returned error: %v", err)
	}
	stream, err := desc.Activate(context.Background(), testStreamEventID)
	if err != nil {
		t.Fatalf("Activate returned error: %v", err)
	}

	if !sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, nil, testStreamBotUserID, testStreamBotDeviceID)) {
		t.Fatal("expected subscribe to be consumed")
	}

	if err = stream.Publish(context.Background(), newTestPublishContent("hello")); err != nil {
		t.Fatalf("Publish returned error: %v", err)
	}
	if sendPath == "" {
		t.Fatal("expected SendToDevice request")
	}
	if !strings.Contains(sendPath, "/sendToDevice/com.beeper.stream.update/") {
		t.Fatalf("unexpected sendToDevice path %q", sendPath)
	}

	var req struct {
		Messages map[string]map[string]json.RawMessage `json:"messages"`
	}
	if err = json.Unmarshal(sendBody, &req); err != nil {
		t.Fatalf("failed to unmarshal sendToDevice request: %v", err)
	}
	targetUser, ok := req.Messages[string(testStreamSubscriberID)]
	if !ok {
		t.Fatalf("missing target user in request: %#v", req.Messages)
	}
	rawContent, ok := targetUser[string(testStreamSubscriberDev)]
	if !ok {
		t.Fatalf("missing target device in request: %#v", targetUser)
	}
	assertStreamUpdateMap(t, decodeJSONMap(t, rawContent))

	if err = stream.Finish(context.Background()); err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}
	if err = stream.Publish(context.Background(), newTestPublishContent("bye")); err == nil {
		t.Fatal("expected Publish after Finish to fail")
	}
}

func TestBeeperStreamHandleAPI(t *testing.T) {
	var sendPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, testStreamBotUserID, "access-token")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	client.DeviceID = testStreamBotDeviceID
	client.StateStore = NewMemoryStateStore()

	publisher := client.NewBeeperStreamPublisher(
		&BeeperStreamPublisherOptions{AuthorizeSubscriber: func(context.Context, *BeeperStreamSubscribeRequest) bool { return true }},
		nil,
	)

	streamDesc, err := publisher.PrepareStream(context.Background(), testStreamRoomID, testStreamType)
	if err != nil {
		t.Fatalf("PrepareStream returned error: %v", err)
	}
	if streamDesc.Info == nil {
		t.Fatal("PrepareStream returned nil Info")
	}
	if streamDesc.Info.UserID != testStreamBotUserID || streamDesc.Info.DeviceID != testStreamBotDeviceID {
		t.Fatalf("PrepareStream descriptor has unexpected identity: %+v", streamDesc.Info)
	}

	stream, err := streamDesc.Activate(context.Background(), testStreamEventID)
	if err != nil {
		t.Fatalf("Activate returned error: %v", err)
	}
	if stream.RoomID() != testStreamRoomID || stream.EventID() != testStreamEventID {
		t.Fatalf("unexpected stream identity: room=%s event=%s", stream.RoomID(), stream.EventID())
	}

	// Subscribe a device so Publish actually sends a to-device event
	sender := client.GetOrCreateBeeperStreamSender(nil)
	if !sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, nil, testStreamBotUserID, testStreamBotDeviceID)) {
		t.Fatal("expected subscribe to be consumed")
	}

	if err = stream.Publish(context.Background(), map[string]any{testStreamDeltaKey: []map[string]any{{"delta": "hi"}}}); err != nil {
		t.Fatalf("Publish returned error: %v", err)
	}
	if !strings.Contains(sendPath, "/sendToDevice/com.beeper.stream.update/") {
		t.Fatalf("unexpected sendToDevice path %q", sendPath)
	}

	if err = stream.Finish(context.Background()); err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}
	if err = stream.Publish(context.Background(), map[string]any{"delta": "bye"}); err == nil {
		t.Fatal("expected Publish after Finish to fail")
	}
}
