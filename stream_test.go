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

func TestNewStreamUpdateContentMarshal(t *testing.T) {
	content, err := newStreamUpdateContent(&PublishStreamRequest{
		RoomID:  "!room:example.com",
		EventID: "$event",
		Content: map[string]any{
			"com.beeper.llm.deltas": []map[string]any{
				{"delta": "hello"},
			},
		},
	})
	if err != nil {
		t.Fatalf("newStreamUpdateContent returned error: %v", err)
	}

	data, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("failed to marshal update content: %v", err)
	}

	var parsed map[string]any
	if err = json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal update content: %v", err)
	}

	if parsed["room_id"] != "!room:example.com" {
		t.Fatalf("unexpected room_id: %#v", parsed["room_id"])
	}
	if parsed["event_id"] != "$event" {
		t.Fatalf("unexpected event_id: %#v", parsed["event_id"])
	}
	if _, ok := parsed["type"]; ok {
		t.Fatalf("unexpected type field: %#v", parsed["type"])
	}
	if _, ok := parsed["content"]; ok {
		t.Fatalf("unexpected nested content field: %#v", parsed["content"])
	}
	if _, ok := parsed["com.beeper.llm.deltas"]; !ok {
		t.Fatalf("missing com.beeper.llm.deltas in marshaled content: %#v", parsed)
	}
}

func TestNewStreamUpdateContentRejectsReservedKeys(t *testing.T) {
	_, err := newStreamUpdateContent(&PublishStreamRequest{
		RoomID:  "!room:example.com",
		EventID: "$event",
		Content: map[string]any{
			"room_id": "override",
		},
	})
	if err == nil {
		t.Fatal("expected room_id override to be rejected")
	}
}

func TestEncryptDecryptStreamPayloadRoundTrip(t *testing.T) {
	key := makeStreamKey()
	content, err := newStreamUpdateContent(&PublishStreamRequest{
		RoomID:  "!room:example.com",
		EventID: "$event",
		Content: map[string]any{
			"com.beeper.llm.deltas": []map[string]any{
				{"delta": "hello"},
			},
		},
	})
	if err != nil {
		t.Fatalf("newStreamUpdateContent returned error: %v", err)
	}

	gcm, err := newStreamGCM(key)
	if err != nil {
		t.Fatalf("newStreamGCM returned error: %v", err)
	}

	encrypted, err := encryptStreamPayload(event.ToDeviceBeeperStreamUpdate, content, "!room:example.com", "$event", gcm)
	if err != nil {
		t.Fatalf("encryptStreamPayload returned error: %v", err)
	}
	if encrypted.Algorithm != id.AlgorithmBeeperStreamAESGCM {
		t.Fatalf("unexpected algorithm: %q", encrypted.Algorithm)
	}
	if encrypted.IV == "" || len(encrypted.StreamCiphertext) == 0 {
		t.Fatalf("encrypted payload missing IV or ciphertext: %#v", encrypted)
	}
	if encrypted.RoomID != "!room:example.com" || encrypted.EventID != "$event" {
		t.Fatalf("encrypted payload missing routing identifiers: %#v", encrypted)
	}

	decrypted, err := decryptStreamPayload(encrypted, gcm)
	if err != nil {
		t.Fatalf("decryptStreamPayload returned error: %v", err)
	}
	if decrypted.Type != event.ToDeviceBeeperStreamUpdate.Type {
		t.Fatalf("unexpected decrypted type: %q", decrypted.Type)
	}

	var parsed map[string]any
	if err = json.Unmarshal(decrypted.Content, &parsed); err != nil {
		t.Fatalf("failed to unmarshal decrypted content: %v", err)
	}
	if parsed["room_id"] != "!room:example.com" || parsed["event_id"] != "$event" {
		t.Fatalf("unexpected decrypted identifiers: %#v", parsed)
	}
	if _, ok := parsed["com.beeper.llm.deltas"]; !ok {
		t.Fatalf("missing com.beeper.llm.deltas in decrypted content: %#v", parsed)
	}
	if _, ok := parsed["type"]; ok {
		t.Fatalf("unexpected type field after decryption: %#v", parsed["type"])
	}
	if _, ok := parsed["content"]; ok {
		t.Fatalf("unexpected nested content field after decryption: %#v", parsed["content"])
	}
}

func TestHandlePlainSubscribe(t *testing.T) {
	helper := NewStreamHelper(&Client{
		UserID:     "@bot:example.com",
		DeviceID:   "BOTDEVICE",
		StateStore: NewMemoryStateStore(),
	}, nil)
	var gotAuth *StreamSubscribeRequest
	gen := helper.NewGenerator(&StreamGeneratorOptions{
		AuthorizeSubscriber: func(_ context.Context, req *StreamSubscribeRequest) bool {
			gotAuth = req
			return req.UserID == "@alice:example.com"
		},
	})
	desc, err := gen.BuildDescriptor(context.Background(), &StreamDescriptorRequest{
		RoomID: "!room:example.com",
		Type:   "com.beeper.llm",
	})
	if err != nil {
		t.Fatalf("BuildDescriptor returned error: %v", err)
	}
	err = gen.Start(context.Background(), &StartStreamRequest{
		RoomID:     "!room:example.com",
		EventID:    "$event",
		Type:       "com.beeper.llm",
		Descriptor: desc,
	})
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	evt := &event.Event{
		Sender: "@alice:example.com",
		Type:   event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
			RoomID:   "!room:example.com",
			EventID:  "$event",
			DeviceID: "SUBDEVICE",
			ExpiryMS: 60_000,
		}},
	}
	if !helper.HandleToDeviceEvent(context.Background(), evt) {
		t.Fatal("expected plain subscribe to be consumed")
	}
	state := helper.streams[streamKey{roomID: "!room:example.com", eventID: "$event"}]
	if state == nil {
		t.Fatal("expected stream state to exist")
	}
	if len(state.subscribers) != 1 {
		t.Fatalf("expected 1 subscriber, got %d", len(state.subscribers))
	}
	if gotAuth == nil {
		t.Fatal("expected authorize callback to be invoked")
	}
	if gotAuth.RoomID != "!room:example.com" || gotAuth.EventID != "$event" || gotAuth.UserID != "@alice:example.com" || gotAuth.DeviceID != "SUBDEVICE" {
		t.Fatalf("unexpected authorize callback request: %#v", gotAuth)
	}
}

func TestPendingPlainSubscribeReplay(t *testing.T) {
	helper := NewStreamHelper(&Client{
		UserID:     "@bot:example.com",
		DeviceID:   "BOTDEVICE",
		StateStore: NewMemoryStateStore(),
	}, nil)
	gen := helper.NewGenerator(&StreamGeneratorOptions{
		AuthorizeSubscriber: func(context.Context, *StreamSubscribeRequest) bool { return true },
	})
	evt := &event.Event{
		Sender: "@alice:example.com",
		Type:   event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
			RoomID:   "!room:example.com",
			EventID:  "$event",
			DeviceID: "SUBDEVICE",
			ExpiryMS: 60_000,
		}},
	}
	if !helper.HandleToDeviceEvent(context.Background(), evt) {
		t.Fatal("expected plain subscribe to be consumed")
	}
	if len(helper.pendingSubscribe) != 1 {
		t.Fatalf("expected 1 pending subscribe, got %d", len(helper.pendingSubscribe))
	}

	desc, err := gen.BuildDescriptor(context.Background(), &StreamDescriptorRequest{
		RoomID: "!room:example.com",
		Type:   "com.beeper.llm",
	})
	if err != nil {
		t.Fatalf("BuildDescriptor returned error: %v", err)
	}
	err = gen.Start(context.Background(), &StartStreamRequest{
		RoomID:     "!room:example.com",
		EventID:    "$event",
		Type:       "com.beeper.llm",
		Descriptor: desc,
	})
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if len(helper.pendingSubscribe) != 0 {
		t.Fatalf("expected pending subscribes to be replayed, got %d left", len(helper.pendingSubscribe))
	}
	state := helper.streams[streamKey{roomID: "!room:example.com", eventID: "$event"}]
	if state == nil {
		t.Fatal("expected stream state to exist")
	}
	if len(state.subscribers) != 1 {
		t.Fatalf("expected 1 replayed subscriber, got %d", len(state.subscribers))
	}
}

func TestPendingEncryptedSubscribeReplay(t *testing.T) {
	helper := NewStreamHelper(&Client{
		UserID:     "@bot:example.com",
		DeviceID:   "BOTDEVICE",
		StateStore: NewMemoryStateStore(),
	}, &StreamHelperOptions{
		IsEncrypted: func(context.Context, id.RoomID) (bool, error) { return true, nil },
	})
	gen := helper.NewGenerator(&StreamGeneratorOptions{
		AuthorizeSubscriber: func(context.Context, *StreamSubscribeRequest) bool { return true },
	})
	desc, err := gen.BuildDescriptor(context.Background(), &StreamDescriptorRequest{
		RoomID: "!room:example.com",
		Type:   "com.beeper.llm",
	})
	if err != nil {
		t.Fatalf("BuildDescriptor returned error: %v", err)
	}
	subscribeContent := &event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
		RoomID:   "!room:example.com",
		EventID:  "$event",
		DeviceID: "SUBDEVICE",
		ExpiryMS: 60_000,
	}}
	testGCM, err := newStreamGCM(desc.Encryption.Key)
	if err != nil {
		t.Fatalf("newStreamGCM returned error: %v", err)
	}
	encrypted, err := encryptStreamPayload(event.ToDeviceBeeperStreamSubscribe, subscribeContent, "!room:example.com", "$event", testGCM)
	if err != nil {
		t.Fatalf("encryptStreamPayload returned error: %v", err)
	}
	evt := &event.Event{
		Sender:  "@alice:example.com",
		Type:    event.ToDeviceEncrypted,
		Content: event.Content{Parsed: encrypted},
	}
	if !helper.HandleToDeviceEvent(context.Background(), evt) {
		t.Fatal("expected encrypted subscribe to be consumed")
	}
	if len(helper.pendingSubscribe) != 1 {
		t.Fatalf("expected 1 pending subscribe, got %d", len(helper.pendingSubscribe))
	}

	err = gen.Start(context.Background(), &StartStreamRequest{
		RoomID:     "!room:example.com",
		EventID:    "$event",
		Type:       "com.beeper.llm",
		Descriptor: desc,
	})
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if len(helper.pendingSubscribe) != 0 {
		t.Fatalf("expected pending subscribes to be replayed, got %d left", len(helper.pendingSubscribe))
	}
	state := helper.streams[streamKey{roomID: "!room:example.com", eventID: "$event"}]
	if state == nil {
		t.Fatal("expected stream state to exist")
	}
	if len(state.subscribers) != 1 {
		t.Fatalf("expected 1 replayed subscriber, got %d", len(state.subscribers))
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

	client, err := NewClient(ts.URL, "@bot:example.com", "access-token")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	client.DeviceID = "BOTDEVICE"
	client.StateStore = NewMemoryStateStore()
	helper := client.GetOrCreateStreamHelper(nil)
	gen := helper.NewGenerator(&StreamGeneratorOptions{
		AuthorizeSubscriber: func(context.Context, *StreamSubscribeRequest) bool { return true },
	})
	desc, err := gen.BuildDescriptor(context.Background(), &StreamDescriptorRequest{
		RoomID: "!room:example.com",
		Type:   "com.beeper.llm",
	})
	if err != nil {
		t.Fatalf("BuildDescriptor returned error: %v", err)
	}
	err = gen.Start(context.Background(), &StartStreamRequest{
		RoomID:     "!room:example.com",
		EventID:    "$event",
		Type:       "com.beeper.llm",
		Descriptor: desc,
	})
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	if !helper.HandleToDeviceEvent(context.Background(), &event.Event{
		Sender:     "@alice:example.com",
		ToUserID:   "@bot:example.com",
		ToDeviceID: "BOTDEVICE",
		Type:       event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
			RoomID:   "!room:example.com",
			EventID:  "$event",
			DeviceID: "SUBDEVICE",
			ExpiryMS: 60_000,
		}},
	}) {
		t.Fatal("expected subscribe to be consumed")
	}

	err = gen.Publish(context.Background(), &PublishStreamRequest{
		RoomID:  "!room:example.com",
		EventID: "$event",
		Content: map[string]any{
			"com.beeper.llm.deltas": []map[string]any{{"delta": "hello"}},
		},
	})
	if err != nil {
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
	targetUser, ok := req.Messages["@alice:example.com"]
	if !ok {
		t.Fatalf("missing target user in request: %#v", req.Messages)
	}
	rawContent, ok := targetUser["SUBDEVICE"]
	if !ok {
		t.Fatalf("missing target device in request: %#v", targetUser)
	}
	var content map[string]any
	if err = json.Unmarshal(rawContent, &content); err != nil {
		t.Fatalf("failed to unmarshal stream update content: %v", err)
	}
	if content["room_id"] != "!room:example.com" || content["event_id"] != "$event" {
		t.Fatalf("unexpected stream update routing content: %#v", content)
	}

	err = gen.Finish(context.Background(), &FinishStreamRequest{
		RoomID:  "!room:example.com",
		EventID: "$event",
	})
	if err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}
	err = gen.Publish(context.Background(), &PublishStreamRequest{
		RoomID:  "!room:example.com",
		EventID: "$event",
		Content: map[string]any{
			"com.beeper.llm.deltas": []map[string]any{{"delta": "bye"}},
		},
	})
	if err == nil {
		t.Fatal("expected Publish after Finish to fail")
	}
}
