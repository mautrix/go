package mautrix

import (
	"context"
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
