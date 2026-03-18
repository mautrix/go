// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
	testStreamPublisherDev  id.DeviceID = "PUBLISHER"
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
		requests: make(chan capturedSendToDeviceRequest, 8),
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		recorder.requests <- capturedSendToDeviceRequest{
			path: r.URL.Path,
			body: body,
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
	client, err := NewClient(homeserverURL, userID, "access-token")
	require.NoError(t, err)
	client.DeviceID = deviceID
	client.StateStore = NewMemoryStateStore()
	return client
}

func newTestPublishContent(delta string) map[string]any {
	return map[string]any{
		testStreamDeltaKey: []map[string]any{{"delta": delta}},
	}
}

func newTestSubscribeEvent(toUserID id.UserID, toDeviceID id.DeviceID) *event.Event {
	return &event.Event{
		Sender:     testStreamSubscriberID,
		ToUserID:   toUserID,
		ToDeviceID: toDeviceID,
		Type:       event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
			RoomID:   testStreamRoomID,
			EventID:  testStreamEventID,
			DeviceID: testStreamSubscriberDev,
			ExpiryMS: 60_000,
		}},
	}
}

func newTestDescriptor(encrypted bool) *event.BeeperStreamInfo {
	descriptor := &event.BeeperStreamInfo{
		UserID:   testStreamBotUserID,
		DeviceID: testStreamPublisherDev,
		Type:     testStreamType,
		ExpiryMS: DefaultBeeperStreamDescriptorExpiry.Milliseconds(),
		Status:   event.BeeperStreamStatusActive,
	}
	if encrypted {
		descriptor.Encryption = &event.BeeperStreamEncryptionInfo{
			Algorithm: id.AlgorithmBeeperStreamAESGCM,
			Key:       makeStreamKey(),
			StreamID:  makeStreamID(),
		}
	}
	return descriptor
}

func newTestEncryptedUpdateEvent(t *testing.T, descriptor *event.BeeperStreamInfo, streamID id.StreamID) *event.Event {
	t.Helper()
	content, err := newUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello"))
	require.NoError(t, err)
	if streamID == "" {
		streamID = descriptor.Encryption.StreamID
	}
	encrypted, err := encryptBeeperStreamEvent(event.ToDeviceBeeperStreamUpdate, content, streamID, descriptor.Encryption.Key)
	require.NoError(t, err)
	return &event.Event{
		Sender:  testStreamBotUserID,
		Type:    event.ToDeviceEncrypted,
		Content: event.Content{Parsed: encrypted},
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
	require.Contains(t, parsed, testStreamDeltaKey)
}

func TestBeeperStreamsNewDescriptor(t *testing.T) {
	client := newTestStreamClient(t, "", testStreamBotUserID, testStreamPublisherDev)
	require.NoError(t, client.StateStore.SetEncryptionEvent(context.Background(), testStreamRoomID, &event.EncryptionEventContent{
		Algorithm: id.AlgorithmMegolmV1,
	}))

	info, err := client.BeeperStreams().NewDescriptor(context.Background(), testStreamRoomID, testStreamType)
	require.NoError(t, err)
	require.Equal(t, testStreamBotUserID, info.UserID)
	require.Equal(t, testStreamPublisherDev, info.DeviceID)
	require.Equal(t, event.BeeperStreamStatusActive, info.Status)
	require.NotNil(t, info.Encryption)
}

func TestBeeperStreamsSubscribeTargetsDescriptorDevice(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, "RECEIVER")
	descriptor := newTestDescriptor(false)

	require.NoError(t, client.BeeperStreams().Subscribe(context.Background(), testStreamRoomID, testStreamEventID, descriptor))
	t.Cleanup(func() { client.BeeperStreams().Unsubscribe(testStreamRoomID, testStreamEventID) })

	req := recorder.next(t)
	require.Contains(t, req.path, "/sendToDevice/com.beeper.stream.subscribe/")
	_ = recorder.rawContent(t, req, testStreamBotUserID, testStreamPublisherDev)
}

func TestBeeperStreamsPublishAndUnregister(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, testStreamPublisherDev)
	streams := client.BeeperStreams()
	streams.SetAuthorizeSubscriber(func(context.Context, *BeeperStreamSubscribeRequest) bool { return true })

	info, err := streams.NewDescriptor(context.Background(), testStreamRoomID, testStreamType)
	require.NoError(t, err)
	require.NoError(t, streams.Register(context.Background(), testStreamRoomID, testStreamEventID, info))

	require.True(t, client.HandleToDeviceEvent(context.Background(), newTestSubscribeEvent(testStreamBotUserID, testStreamPublisherDev)))

	require.NoError(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	req := recorder.next(t)
	require.Contains(t, req.path, "/sendToDevice/com.beeper.stream.update/")
	assertStreamUpdateMap(t, decodeJSONMap(t, recorder.rawContent(t, req, testStreamSubscriberID, testStreamSubscriberDev)))

	streams.Unregister(testStreamRoomID, testStreamEventID)
	require.Error(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("bye")))
}

func TestBeeperStreamsEncryptedUpdatesReachListeners(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, "RECEIVER")
	descriptor := newTestDescriptor(true)

	require.NoError(t, client.BeeperStreams().Subscribe(context.Background(), testStreamRoomID, testStreamEventID, descriptor))
	t.Cleanup(func() { client.BeeperStreams().Unsubscribe(testStreamRoomID, testStreamEventID) })
	_ = recorder.next(t) // initial subscribe

	received := make(chan *event.Event, 1)
	syncer := client.Syncer.(*DefaultSyncer)
	syncer.OnEventType(event.ToDeviceBeeperStreamUpdate, func(_ context.Context, evt *event.Event) {
		received <- evt
	})

	evt := newTestEncryptedUpdateEvent(t, descriptor, "")
	syncer.processSyncEvent(context.Background(), "", evt, event.SourceToDevice, false)

	select {
	case got := <-received:
		require.Equal(t, event.ToDeviceBeeperStreamUpdate, got.Type)
		update := got.Content.AsBeeperStreamUpdate()
		require.Equal(t, testStreamRoomID, update.RoomID)
		require.Equal(t, testStreamEventID, update.EventID)
		require.Contains(t, got.Content.Raw, testStreamDeltaKey)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for normalized beeper stream update")
	}
}
