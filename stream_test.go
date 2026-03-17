package mautrix

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	testStreamRoomID        id.RoomID   = "!room:example.com"
	testStreamEventID       id.EventID  = "$event"
	testStreamType                      = "com.beeper.llm"
	testStreamBotUserID     id.UserID   = "@bot:example.com"
	testStreamSubscriberID  id.UserID   = "@alice:example.com"
	testStreamSubscriberDev id.DeviceID = "SUBDEVICE"
	testStreamDeltaKey                  = "com.beeper.llm.deltas"
)

type capturedSendToDeviceRequest struct {
	path string
	body []byte
}

type sendToDeviceRecorder struct {
	requests chan capturedSendToDeviceRequest
}

func newSendToDeviceRecorderServer(t *testing.T) (*httptest.Server, *sendToDeviceRecorder) {
	t.Helper()
	recorder := &sendToDeviceRecorder{
		requests: make(chan capturedSendToDeviceRequest, 4),
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected method %s", r.Method)
		}
		recorder.requests <- capturedSendToDeviceRequest{
			path: r.URL.Path,
			body: must(io.ReadAll(r.Body)),
		}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	t.Cleanup(ts.Close)
	return ts, recorder
}

func (r *sendToDeviceRecorder) next(t *testing.T) capturedSendToDeviceRequest {
	t.Helper()
	select {
	case req := <-r.requests:
		return req
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sendToDevice request")
		return capturedSendToDeviceRequest{}
	}
}

func (r *sendToDeviceRecorder) rawContent(t *testing.T, req capturedSendToDeviceRequest, userID id.UserID, deviceID id.DeviceID) json.RawMessage {
	t.Helper()
	var payload struct {
		Messages map[string]map[string]json.RawMessage `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(req.body, &payload))
	require.Contains(t, payload.Messages, string(userID), "missing target user in request")
	require.Contains(t, payload.Messages[string(userID)], string(deviceID), "missing target device in request")
	return payload.Messages[string(userID)][string(deviceID)]
}

func newTestStreamClient(t *testing.T, homeserverURL string, userID id.UserID, deviceID id.DeviceID) *Client {
	t.Helper()
	client := must(NewClient(homeserverURL, userID, "access-token"))
	client.DeviceID = deviceID
	client.StateStore = NewMemoryStateStore()
	return client
}

func newTestStreamWithDesc(t *testing.T, encrypted bool, authorize func(context.Context, *BeeperStreamSubscribeRequest) bool) (*BeeperStreamSender, *BeeperStreamDescriptor) {
	t.Helper()
	opts := &BeeperStreamSenderOptions{AuthorizeSubscriber: authorize}
	if encrypted {
		opts.IsEncrypted = func(context.Context, id.RoomID) (bool, error) { return true, nil }
	}
	sender := NewBeeperStreamSender(&Client{
		UserID:     testStreamBotUserID,
		StateStore: NewMemoryStateStore(),
	}, opts)
	return sender, must(sender.PrepareStream(context.Background(), testStreamRoomID, testStreamType))
}

func newEncryptedTestDesc(t *testing.T) (*BeeperStreamSender, *BeeperStreamDescriptor) {
	t.Helper()
	return newTestStreamWithDesc(t, true, func(context.Context, *BeeperStreamSubscribeRequest) bool { return true })
}

func startTestStream(t *testing.T, desc *BeeperStreamDescriptor) *BeeperStream {
	t.Helper()
	return must(desc.Activate(context.Background(), testStreamEventID))
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
		gcm := must(newStreamGCM(desc.Encryption.Key))
		encrypted := must(encryptStreamPayload(event.ToDeviceBeeperStreamSubscribe, content, desc.Encryption.StreamID, gcm))
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
	require.NoError(t, json.Unmarshal(data, &parsed))
	return parsed
}

func assertStreamUpdateMap(t *testing.T, parsed map[string]any) {
	t.Helper()
	require.Equal(t, string(testStreamRoomID), parsed["room_id"])
	require.Equal(t, string(testStreamEventID), parsed["event_id"])
	require.NotContains(t, parsed, "type")
	require.NotContains(t, parsed, "content")
	require.Contains(t, parsed, testStreamDeltaKey)
}

func requireTestStreamState(t *testing.T, sender *BeeperStreamSender) *beeperStreamState {
	t.Helper()
	state := sender.streams[beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID}]
	require.NotNil(t, state, "expected stream state to exist")
	return state
}

func assertTestStreamSubscribe(t *testing.T, recorder *sendToDeviceRecorder, userID id.UserID, deviceID id.DeviceID) {
	t.Helper()
	req := recorder.next(t)
	if !strings.Contains(req.path, "/sendToDevice/com.beeper.stream.subscribe/") {
		t.Fatalf("unexpected sendToDevice path %q", req.path)
	}
	var subscribe event.BeeperStreamSubscribeEventContent
	require.NoError(t, json.Unmarshal(recorder.rawContent(t, req, userID, deviceID), &subscribe))
	require.Equal(t, testStreamRoomID, subscribe.RoomID)
	require.Equal(t, testStreamEventID, subscribe.EventID)
	require.Equal(t, testStreamSubscriberDev, subscribe.DeviceID)
}

func assertTestStreamUpdate(t *testing.T, recorder *sendToDeviceRecorder, userID id.UserID, deviceID id.DeviceID) {
	t.Helper()
	req := recorder.next(t)
	if !strings.Contains(req.path, "/sendToDevice/com.beeper.stream.update/") {
		t.Fatalf("unexpected sendToDevice path %q", req.path)
	}
	assertStreamUpdateMap(t, decodeJSONMap(t, recorder.rawContent(t, req, userID, deviceID)))
}

func must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

func TestNewStreamUpdateContentMarshal(t *testing.T) {
	content := must(newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	assertStreamUpdateMap(t, decodeJSONMap(t, must(json.Marshal(content))))
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

func TestNewStreamUpdateContentAllowsNilPayload(t *testing.T) {
	content := must(newStreamUpdateContent(testStreamRoomID, testStreamEventID, nil))
	parsed := decodeJSONMap(t, must(json.Marshal(content)))
	if parsed["room_id"] != string(testStreamRoomID) {
		t.Fatalf("unexpected room_id: %#v", parsed["room_id"])
	}
	if parsed["event_id"] != string(testStreamEventID) {
		t.Fatalf("unexpected event_id: %#v", parsed["event_id"])
	}
	if len(parsed) != 2 {
		t.Fatalf("expected only room_id and event_id in nil payload update, got %#v", parsed)
	}
}

func TestEncryptDecryptStreamPayloadRoundTrip(t *testing.T) {
	key := makeStreamKey()
	content := must(newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	gcm := must(newStreamGCM(key))
	streamID := makeStreamID()
	encrypted := must(encryptStreamPayload(event.ToDeviceBeeperStreamUpdate, content, streamID, gcm))
	if encrypted.Algorithm != id.AlgorithmBeeperStreamAESGCM {
		t.Fatalf("unexpected algorithm: %q", encrypted.Algorithm)
	}
	if encrypted.IV == "" || len(encrypted.StreamCiphertext) == 0 {
		t.Fatalf("encrypted payload missing IV or ciphertext: %#v", encrypted)
	}
	if encrypted.StreamID != streamID {
		t.Fatalf("encrypted payload missing stream ID: %#v", encrypted)
	}

	decrypted := must(decryptStreamPayload(encrypted, gcm))
	if decrypted.Type != event.ToDeviceBeeperStreamUpdate.Type {
		t.Fatalf("unexpected decrypted type: %q", decrypted.Type)
	}
	assertStreamUpdateMap(t, decodeJSONMap(t, decrypted.Content))
}

func TestDecryptStreamPayloadRejectsInvalidIVLength(t *testing.T) {
	gcm := must(newStreamGCM(makeStreamKey()))
	_, err := decryptStreamPayload(&event.EncryptedEventContent{
		IV:               base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3}),
		StreamCiphertext: base64.RawStdEncoding.AppendEncode(nil, []byte("payload")),
	}, gcm)
	if err == nil {
		t.Fatal("expected invalid IV length to fail")
	}
	if !strings.Contains(err.Error(), "invalid beeper stream IV length") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandlePlainSubscribe(t *testing.T) {
	var gotAuth *BeeperStreamSubscribeRequest
	sender, desc := newTestStreamWithDesc(t, false, func(_ context.Context, req *BeeperStreamSubscribeRequest) bool {
		gotAuth = req
		return req.UserID == testStreamSubscriberID
	})
	startTestStream(t, desc)

	if !sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, nil, testStreamBotUserID, "*")) {
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
			sender, desc := newTestStreamWithDesc(t, tc.encrypted, func(context.Context, *BeeperStreamSubscribeRequest) bool {
				return true
			})

			if !sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, desc.Info, testStreamBotUserID, "*")) {
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

func TestHandleEncryptedSubscribeWithoutStreamIDDropped(t *testing.T) {
	sender, desc := newEncryptedTestDesc(t)
	encrypted := must(EncryptBeeperStreamEvent(event.ToDeviceBeeperStreamSubscribe, newTestSubscribeContent(), "", desc.Info.Encryption.Key))
	if !sender.HandleToDeviceEvent(context.Background(), &event.Event{
		Sender:  testStreamSubscriberID,
		Type:    event.ToDeviceEncrypted,
		Content: event.Content{Parsed: encrypted},
	}) {
		t.Fatal("expected encrypted subscribe to be consumed")
	}
	if len(sender.pendingSubscribe) != 0 {
		t.Fatalf("expected encrypted subscribe without stream_id to be dropped, got %d pending", len(sender.pendingSubscribe))
	}
}

func TestBeeperStreamDescriptorActivateRejectsInvalidEncryptedDescriptor(t *testing.T) {
	_, desc := newEncryptedTestDesc(t)
	desc.Info.Encryption.StreamID = ""
	if _, err := desc.Activate(context.Background(), testStreamEventID); err == nil {
		t.Fatal("expected Activate to fail with missing encrypted stream_id")
	}
}

func TestBeeperStreamDescriptorActivateOneShot(t *testing.T) {
	_, desc := newEncryptedTestDesc(t)
	must(desc.Activate(context.Background(), testStreamEventID))
	if _, err := desc.Activate(context.Background(), "$second"); err == nil {
		t.Fatal("expected second Activate on same descriptor to fail")
	}
}

func TestBeeperStreamDescriptorActivateRejectsStreamIDCollision(t *testing.T) {
	sender, descA := newEncryptedTestDesc(t)
	must(descA.Activate(context.Background(), testStreamEventID))
	descB := must(sender.PrepareStream(context.Background(), testStreamRoomID, testStreamType))
	descB.Info.Encryption.StreamID = descA.Info.Encryption.StreamID
	if _, err := descB.Activate(context.Background(), "$second"); err == nil {
		t.Fatal("expected Activate to fail on stream_id collision")
	}
	if _, exists := sender.streams[beeperStreamKey{roomID: testStreamRoomID, eventID: "$second"}]; exists {
		t.Fatal("unexpected stream state for failed activation")
	}
}

func TestBeeperStreamDescriptorActivateSnapshotsDescriptor(t *testing.T) {
	sender, desc := newEncryptedTestDesc(t)
	originalInfo := *desc.Info
	originalEnc := *desc.Info.Encryption
	originalInfo.Encryption = &originalEnc
	original := &originalInfo
	must(desc.Activate(context.Background(), testStreamEventID))
	state := requireTestStreamState(t, sender)
	if state.descriptor == desc.Info {
		t.Fatal("expected activated stream descriptor to be copied")
	}
	if state.descriptor.Encryption == desc.Info.Encryption {
		t.Fatal("expected activated stream encryption descriptor to be deep-copied")
	}
	desc.Info.Encryption.StreamID = makeStreamID()
	if state.descriptor.Encryption.StreamID != original.Encryption.StreamID {
		t.Fatal("expected stream state to keep original stream_id after descriptor mutation")
	}
	if !sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, original, testStreamBotUserID, "*")) {
		t.Fatal("expected encrypted subscribe to be consumed")
	}
	if len(state.subscribers) != 1 {
		t.Fatalf("expected 1 subscriber from original stream_id, got %d", len(state.subscribers))
	}
}

func TestStreamPublishAndFinish(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, "")

	sender := client.GetOrCreateBeeperStreamSender(&BeeperStreamSenderOptions{
		AuthorizeSubscriber: func(context.Context, *BeeperStreamSubscribeRequest) bool { return true },
	})
	streamDesc := must(sender.PrepareStream(context.Background(), testStreamRoomID, testStreamType))
	if streamDesc.Info == nil {
		t.Fatal("PrepareStream returned nil Info")
	}
	if streamDesc.Info.UserID != testStreamBotUserID {
		t.Fatalf("PrepareStream descriptor has unexpected identity: %+v", streamDesc.Info)
	}

	stream := must(streamDesc.Activate(context.Background(), testStreamEventID))

	if !sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, nil, testStreamBotUserID, "*")) {
		t.Fatal("expected subscribe to be consumed")
	}

	require.NoError(t, stream.Publish(context.Background(), newTestPublishContent("hello")))
	assertTestStreamUpdate(t, recorder, testStreamSubscriberID, testStreamSubscriberDev)

	require.NoError(t, stream.Finish(context.Background()))
	if err := stream.Publish(context.Background(), newTestPublishContent("bye")); err == nil {
		t.Fatal("expected Publish after Finish to fail")
	}
}
