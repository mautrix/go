package mautrix

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
		require.Equal(t, http.MethodPut, r.Method)
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
	require.Contains(t, req.path, "/sendToDevice/com.beeper.stream.subscribe/")
	var subscribe event.BeeperStreamSubscribeEventContent
	require.NoError(t, json.Unmarshal(recorder.rawContent(t, req, userID, deviceID), &subscribe))
	require.Equal(t, testStreamRoomID, subscribe.RoomID)
	require.Equal(t, testStreamEventID, subscribe.EventID)
	require.Equal(t, testStreamSubscriberDev, subscribe.DeviceID)
}

func assertTestStreamUpdate(t *testing.T, recorder *sendToDeviceRecorder, userID id.UserID, deviceID id.DeviceID) {
	t.Helper()
	req := recorder.next(t)
	require.Contains(t, req.path, "/sendToDevice/com.beeper.stream.update/")
	assertStreamUpdateMap(t, decodeJSONMap(t, recorder.rawContent(t, req, userID, deviceID)))
}

func must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

func TestStreamUpdateContent(t *testing.T) {
	// with payload produces correct flattened structure
	content := must(newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	assertStreamUpdateMap(t, decodeJSONMap(t, must(json.Marshal(content))))

	// nil payload produces only room_id and event_id
	content = must(newStreamUpdateContent(testStreamRoomID, testStreamEventID, nil))
	parsed := decodeJSONMap(t, must(json.Marshal(content)))
	require.Equal(t, string(testStreamRoomID), parsed["room_id"])
	require.Equal(t, string(testStreamEventID), parsed["event_id"])
	require.Len(t, parsed, 2)

	// reserved keys rejected
	for _, key := range []string{"room_id", "event_id"} {
		bad := newTestPublishContent("hello")
		bad[key] = "override"
		_, err := newStreamUpdateContent(testStreamRoomID, testStreamEventID, bad)
		require.Error(t, err)
	}
}

func TestStreamPayloadCrypto(t *testing.T) {
	content := must(newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	gcm := must(newStreamGCM(makeStreamKey()))
	streamID := makeStreamID()
	encrypted := must(encryptStreamPayload(event.ToDeviceBeeperStreamUpdate, content, streamID, gcm))
	require.Equal(t, id.AlgorithmBeeperStreamAESGCM, encrypted.Algorithm)
	require.NotEmpty(t, encrypted.IV)
	require.NotEmpty(t, encrypted.StreamCiphertext)
	require.Equal(t, streamID, encrypted.StreamID)

	decrypted := must(decryptStreamPayload(encrypted, gcm))
	require.Equal(t, event.ToDeviceBeeperStreamUpdate.Type, decrypted.Type)
	assertStreamUpdateMap(t, decodeJSONMap(t, decrypted.Content))

	_, err := decryptStreamPayload(&event.EncryptedEventContent{
		IV:               base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3}),
		StreamCiphertext: base64.RawStdEncoding.AppendEncode(nil, []byte("payload")),
	}, gcm)
	require.ErrorContains(t, err, "invalid beeper stream IV length")
}

func TestHandlePlainSubscribe(t *testing.T) {
	var gotAuth *BeeperStreamSubscribeRequest
	sender, desc := newTestStreamWithDesc(t, false, func(_ context.Context, req *BeeperStreamSubscribeRequest) bool {
		gotAuth = req
		return req.UserID == testStreamSubscriberID
	})
	startTestStream(t, desc)

	require.True(t, sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, nil, testStreamBotUserID, "*")))

	state := requireTestStreamState(t, sender)
	require.Len(t, state.subscribers, 1)
	require.NotNil(t, gotAuth)
	require.Equal(t, testStreamRoomID, gotAuth.RoomID)
	require.Equal(t, testStreamEventID, gotAuth.EventID)
	require.Equal(t, testStreamSubscriberID, gotAuth.UserID)
	require.Equal(t, testStreamSubscriberDev, gotAuth.DeviceID)
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

			require.True(t, sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, desc.Info, testStreamBotUserID, "*")))
			require.Len(t, sender.pendingSubscribe, 1)

			startTestStream(t, desc)

			require.Empty(t, sender.pendingSubscribe)
			state := requireTestStreamState(t, sender)
			require.Len(t, state.subscribers, 1)
		})
	}
}

func TestHandleEncryptedSubscribeWithoutStreamIDDropped(t *testing.T) {
	sender, desc := newEncryptedTestDesc(t)
	encrypted := must(EncryptBeeperStreamEvent(event.ToDeviceBeeperStreamSubscribe, newTestSubscribeContent(), "", desc.Info.Encryption.Key))
	require.True(t, sender.HandleToDeviceEvent(context.Background(), &event.Event{
		Sender:  testStreamSubscriberID,
		Type:    event.ToDeviceEncrypted,
		Content: event.Content{Parsed: encrypted},
	}))
	require.Empty(t, sender.pendingSubscribe)
}

func TestBeeperStreamDescriptorActivate(t *testing.T) {
	// missing stream_id rejected
	_, desc := newEncryptedTestDesc(t)
	desc.Info.Encryption.StreamID = ""
	_, err := desc.Activate(context.Background(), testStreamEventID)
	require.Error(t, err)

	// one-shot: second activate on same descriptor fails
	_, desc = newEncryptedTestDesc(t)
	must(desc.Activate(context.Background(), testStreamEventID))
	_, err = desc.Activate(context.Background(), "$second")
	require.Error(t, err)

	// stream_id collision rejected, no state left behind
	sender, descA := newEncryptedTestDesc(t)
	must(descA.Activate(context.Background(), testStreamEventID))
	descB := must(sender.PrepareStream(context.Background(), testStreamRoomID, testStreamType))
	descB.Info.Encryption.StreamID = descA.Info.Encryption.StreamID
	_, err = descB.Activate(context.Background(), "$second")
	require.Error(t, err)
	require.NotContains(t, sender.streams, beeperStreamKey{roomID: testStreamRoomID, eventID: "$second"})
}

func TestBeeperStreamDescriptorActivateSnapshotsDescriptor(t *testing.T) {
	sender, desc := newEncryptedTestDesc(t)
	originalInfo := *desc.Info
	originalEnc := *desc.Info.Encryption
	originalInfo.Encryption = &originalEnc
	original := &originalInfo
	must(desc.Activate(context.Background(), testStreamEventID))
	state := requireTestStreamState(t, sender)
	require.NotSame(t, desc.Info, state.descriptor)
	require.NotSame(t, desc.Info.Encryption, state.descriptor.Encryption)
	desc.Info.Encryption.StreamID = makeStreamID()
	require.Equal(t, original.Encryption.StreamID, state.descriptor.Encryption.StreamID)
	require.True(t, sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, original, testStreamBotUserID, "*")))
	require.Len(t, state.subscribers, 1)
}

func TestStreamPublishAndFinish(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, "")

	sender := client.GetOrCreateBeeperStreamSender(&BeeperStreamSenderOptions{
		AuthorizeSubscriber: func(context.Context, *BeeperStreamSubscribeRequest) bool { return true },
	})
	streamDesc := must(sender.PrepareStream(context.Background(), testStreamRoomID, testStreamType))
	require.NotNil(t, streamDesc.Info)
	require.Equal(t, testStreamBotUserID, streamDesc.Info.UserID)

	stream := must(streamDesc.Activate(context.Background(), testStreamEventID))

	require.True(t, sender.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(t, nil, testStreamBotUserID, "*")))

	require.NoError(t, stream.Publish(context.Background(), newTestPublishContent("hello")))
	assertTestStreamUpdate(t, recorder, testStreamSubscriberID, testStreamSubscriberDev)

	require.NoError(t, stream.Finish(context.Background()))
	require.Error(t, stream.Publish(context.Background(), newTestPublishContent("bye")))
}
