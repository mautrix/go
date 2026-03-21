// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package beeperstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix"
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

func newTestStreamClient(t *testing.T, homeserverURL string, userID id.UserID, deviceID id.DeviceID) *mautrix.Client {
	t.Helper()
	client, err := mautrix.NewClient(homeserverURL, userID, "access-token")
	require.NoError(t, err)
	client.DeviceID = deviceID
	client.StateStore = mautrix.NewMemoryStateStore()
	return client
}

func newTestHelper(t *testing.T, client *mautrix.Client) *Helper {
	t.Helper()
	helper, err := New(client)
	require.NoError(t, err)
	return helper
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

func newTestEncryptedSubscribeEvent(t *testing.T, descriptor *event.BeeperStreamInfo) *event.Event {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"device_id": testStreamSubscriberDev,
		"expiry_ms": 60_000,
	})
	require.NoError(t, err)
	encrypted, err := encryptLogicalEvent(event.ToDeviceBeeperStreamSubscribe, payload, testStreamRoomID, testStreamEventID, descriptor.Encryption.Key)
	require.NoError(t, err)
	return &event.Event{
		Sender:     testStreamSubscriberID,
		ToUserID:   testStreamBotUserID,
		ToDeviceID: testStreamPublisherDev,
		Type:       event.ToDeviceEncrypted,
		Content:    event.Content{Parsed: encrypted},
	}
}

func newTestDescriptor(encrypted bool) *event.BeeperStreamInfo {
	descriptor := &event.BeeperStreamInfo{
		UserID:   testStreamBotUserID,
		DeviceID: testStreamPublisherDev,
		Type:     testStreamType,
		ExpiryMS: DefaultDescriptorExpiry.Milliseconds(),
	}
	if encrypted {
		descriptor.Encryption = &event.BeeperStreamEncryptionInfo{
			Algorithm: id.AlgorithmBeeperStreamAESGCM,
			Key:       makeStreamKey(),
		}
	}
	return descriptor
}

func newTestEncryptedUpdateEvent(t *testing.T, descriptor *event.BeeperStreamInfo) *event.Event {
	t.Helper()
	content, err := newUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello"))
	require.NoError(t, err)
	raw, err := rawMapFromContent(content)
	require.NoError(t, err)
	payload, err := json.Marshal(removeStreamRouting(raw))
	require.NoError(t, err)
	encrypted, err := encryptLogicalEvent(event.ToDeviceBeeperStreamUpdate, payload, testStreamRoomID, testStreamEventID, descriptor.Encryption.Key)
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
	require.Equal(t, string(testStreamRoomID), fmt.Sprint(parsed["room_id"]))
	require.Equal(t, string(testStreamEventID), fmt.Sprint(parsed["event_id"]))
	require.Contains(t, parsed, testStreamDeltaKey)
}

func TestHelperNewDescriptor(t *testing.T) {
	client := newTestStreamClient(t, "", testStreamBotUserID, testStreamPublisherDev)
	require.NoError(t, client.StateStore.SetEncryptionEvent(context.Background(), testStreamRoomID, &event.EncryptionEventContent{
		Algorithm: id.AlgorithmMegolmV1,
	}))

	info, err := newTestHelper(t, client).NewDescriptor(context.Background(), testStreamRoomID, testStreamType)
	require.NoError(t, err)
	require.Equal(t, testStreamBotUserID, info.UserID)
	require.Equal(t, testStreamPublisherDev, info.DeviceID)
	require.NotNil(t, info.Encryption)
}

func TestHelperSubscribeTargetsDescriptorDevice(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, "RECEIVER")
	streams := newTestHelper(t, client)
	descriptor := newTestDescriptor(false)

	require.NoError(t, streams.Subscribe(context.Background(), testStreamRoomID, testStreamEventID, descriptor))
	t.Cleanup(func() { streams.Unsubscribe(testStreamRoomID, testStreamEventID) })

	req := recorder.next(t)
	require.Contains(t, req.path, "/sendToDevice/com.beeper.stream.subscribe/")
	_ = recorder.rawContent(t, req, testStreamBotUserID, testStreamPublisherDev)
}

func TestHelperPublishAndUnregister(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, testStreamPublisherDev)
	streams := newTestHelper(t, client)

	info, err := streams.NewDescriptor(context.Background(), testStreamRoomID, testStreamType)
	require.NoError(t, err)
	require.NoError(t, streams.Register(context.Background(), testStreamRoomID, testStreamEventID, info))

	require.Nil(t, streams.handleEvent(context.Background(), newTestSubscribeEvent(testStreamBotUserID, testStreamPublisherDev)))

	require.NoError(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	req := recorder.next(t)
	require.Contains(t, req.path, "/sendToDevice/com.beeper.stream.update/")
	assertStreamUpdateMap(t, decodeJSONMap(t, recorder.rawContent(t, req, testStreamSubscriberID, testStreamSubscriberDev)))

	streams.Unregister(testStreamRoomID, testStreamEventID)
	require.Error(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("bye")))
}

func TestHelperReplayPendingSubscribeOnRegister(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, testStreamPublisherDev)
	streams := newTestHelper(t, client)

	require.Nil(t, streams.handleEvent(context.Background(), newTestSubscribeEvent(testStreamBotUserID, testStreamPublisherDev)))

	require.NoError(t, streams.Register(context.Background(), testStreamRoomID, testStreamEventID, newTestDescriptor(false)))
	require.NoError(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))

	req := recorder.next(t)
	require.Contains(t, req.path, "/sendToDevice/com.beeper.stream.update/")
	assertStreamUpdateMap(t, decodeJSONMap(t, recorder.rawContent(t, req, testStreamSubscriberID, testStreamSubscriberDev)))
}

func TestHelperReplayPendingEncryptedSubscribeOnRegister(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, testStreamPublisherDev)
	streams := newTestHelper(t, client)
	descriptor := newTestDescriptor(true)

	require.Nil(t, streams.handleEvent(context.Background(), newTestEncryptedSubscribeEvent(t, descriptor)))

	require.NoError(t, streams.Register(context.Background(), testStreamRoomID, testStreamEventID, descriptor))
	require.NoError(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))

	req := recorder.next(t)
	require.Contains(t, req.path, "/sendToDevice/m.room.encrypted/")
	rawContent := recorder.rawContent(t, req, testStreamSubscriberID, testStreamSubscriberDev)
	var payload event.EncryptedEventContent
	require.NoError(t, json.Unmarshal(rawContent, &payload))
	logicalType, payloadContent, err := decryptLogicalEvent(&payload, descriptor.Encryption.Key)
	require.NoError(t, err)
	require.Equal(t, event.ToDeviceBeeperStreamUpdate, logicalType)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(payloadContent, &parsed))
	parsed["room_id"] = testStreamRoomID
	parsed["event_id"] = testStreamEventID
	assertStreamUpdateMap(t, parsed)
}

func TestHelperHandleSyncResponseForwardsBridgeSubscribe(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, testStreamPublisherDev)
	streams := newTestHelper(t, client)

	info, err := streams.NewDescriptor(context.Background(), testStreamRoomID, testStreamType)
	require.NoError(t, err)
	require.NoError(t, streams.Register(context.Background(), testStreamRoomID, testStreamEventID, info))

	streams.HandleSyncResponse(context.Background(), &mautrix.RespSync{
		ToDevice: mautrix.SyncEventsList{Events: []*event.Event{
			newTestSubscribeEvent(testStreamBotUserID, testStreamPublisherDev),
		}},
	})

	require.NoError(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	req := recorder.next(t)
	require.Contains(t, req.path, "/sendToDevice/com.beeper.stream.update/")
	assertStreamUpdateMap(t, decodeJSONMap(t, recorder.rawContent(t, req, testStreamSubscriberID, testStreamSubscriberDev)))
}

func TestHelperHandleSyncResponseIgnoresWrongDevice(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, testStreamPublisherDev)
	streams := newTestHelper(t, client)

	info, err := streams.NewDescriptor(context.Background(), testStreamRoomID, testStreamType)
	require.NoError(t, err)
	require.NoError(t, streams.Register(context.Background(), testStreamRoomID, testStreamEventID, info))

	streams.HandleSyncResponse(context.Background(), &mautrix.RespSync{
		ToDevice: mautrix.SyncEventsList{Events: []*event.Event{
			newTestSubscribeEvent(testStreamBotUserID, "OTHERDEVICE"),
		}},
	})

	require.NoError(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	select {
	case req := <-recorder.requests:
		t.Fatalf("unexpected sendToDevice request: %s", req.path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHelperHandleSyncResponseIgnoresWrongUser(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, testStreamPublisherDev)
	streams := newTestHelper(t, client)

	info, err := streams.NewDescriptor(context.Background(), testStreamRoomID, testStreamType)
	require.NoError(t, err)
	require.NoError(t, streams.Register(context.Background(), testStreamRoomID, testStreamEventID, info))

	streams.HandleSyncResponse(context.Background(), &mautrix.RespSync{
		ToDevice: mautrix.SyncEventsList{Events: []*event.Event{
			newTestSubscribeEvent("@other:example.com", testStreamPublisherDev),
		}},
	})

	require.NoError(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	select {
	case req := <-recorder.requests:
		t.Fatalf("unexpected sendToDevice request: %s", req.path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHelperHandleSyncResponseIgnoresWrongDeviceWithoutUserID(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, testStreamPublisherDev)
	streams := newTestHelper(t, client)

	info, err := streams.NewDescriptor(context.Background(), testStreamRoomID, testStreamType)
	require.NoError(t, err)
	require.NoError(t, streams.Register(context.Background(), testStreamRoomID, testStreamEventID, info))

	streams.HandleSyncResponse(context.Background(), &mautrix.RespSync{
		ToDevice: mautrix.SyncEventsList{Events: []*event.Event{
			newTestSubscribeEvent("", "OTHERDEVICE"),
		}},
	})

	require.NoError(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	select {
	case req := <-recorder.requests:
		t.Fatalf("unexpected sendToDevice request: %s", req.path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHelperHandleSyncResponseReturnsNormalizedEvents(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, "RECEIVER")
	streams := newTestHelper(t, client)
	descriptor := newTestDescriptor(true)

	require.NoError(t, streams.Subscribe(context.Background(), testStreamRoomID, testStreamEventID, descriptor))
	t.Cleanup(func() { streams.Unsubscribe(testStreamRoomID, testStreamEventID) })
	_ = recorder.next(t)

	normalized := streams.HandleSyncResponse(context.Background(), &mautrix.RespSync{
		ToDevice: mautrix.SyncEventsList{Events: []*event.Event{newTestEncryptedUpdateEvent(t, descriptor)}},
	})

	require.Len(t, normalized, 1)
	require.Equal(t, event.ToDeviceBeeperStreamUpdate, normalized[0].Type)
	require.Equal(t, testStreamRoomID, normalized[0].RoomID)
	update := normalized[0].Content.AsBeeperStreamUpdate()
	require.Equal(t, testStreamRoomID, update.RoomID)
	require.Equal(t, testStreamEventID, update.EventID)
	require.Contains(t, normalized[0].Content.Raw, testStreamDeltaKey)
}

func TestHelperInitIsIdempotent(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, "RECEIVER")
	streams := newTestHelper(t, client)
	descriptor := newTestDescriptor(true)

	require.NoError(t, streams.Init(context.Background()))
	require.NoError(t, streams.Init(context.Background()))
	require.NoError(t, streams.Subscribe(context.Background(), testStreamRoomID, testStreamEventID, descriptor))
	t.Cleanup(func() {
		streams.Unsubscribe(testStreamRoomID, testStreamEventID)
		_ = streams.Close()
	})
	_ = recorder.next(t)

	received := make(chan *event.Event, 2)
	syncer := client.Syncer.(*mautrix.DefaultSyncer)
	syncer.OnEventType(event.ToDeviceBeeperStreamUpdate, func(_ context.Context, evt *event.Event) {
		received <- evt
	})

	evt := newTestEncryptedUpdateEvent(t, descriptor)
	syncer.ProcessResponse(context.Background(), &mautrix.RespSync{
		ToDevice: mautrix.SyncEventsList{Events: []*event.Event{evt}},
	}, "")

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

	select {
	case extra := <-received:
		t.Fatalf("unexpected duplicate beeper stream update: %+v", extra)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHelperPendingSubscribeExpiresBeforeRegister(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamBotUserID, testStreamPublisherDev)
	streams := newTestHelper(t, client)
	now := time.Unix(1_000, 0)
	streams.now = func() time.Time { return now }

	require.Nil(t, streams.handleEvent(context.Background(), newTestSubscribeEvent(testStreamBotUserID, testStreamPublisherDev)))

	now = now.Add(pendingSubscribeTTL + time.Second)
	require.NoError(t, streams.Register(context.Background(), testStreamRoomID, testStreamEventID, newTestDescriptor(false)))
	require.NoError(t, streams.Publish(context.Background(), testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))

	select {
	case req := <-recorder.requests:
		t.Fatalf("unexpected sendToDevice request: %s", req.path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHelperPendingSubscribeQueueTrim(t *testing.T) {
	client := newTestStreamClient(t, "", testStreamBotUserID, testStreamPublisherDev)
	streams := newTestHelper(t, client)

	for i := 0; i < maxPendingSubscriptions+1; i++ {
		evt := &event.Event{
			Sender: testStreamSubscriberID,
			Type:   event.ToDeviceBeeperStreamSubscribe,
			Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
				RoomID:   id.RoomID(testStreamRoomID + id.RoomID(fmt.Sprintf("-%d", i))),
				EventID:  testStreamEventID,
				DeviceID: testStreamSubscriberDev,
				ExpiryMS: 60_000,
			}},
		}
		streams.queuePendingSubscribe(context.Background(), evt)
	}

	require.Len(t, streams.pendingSubscribe, maxPendingSubscriptions)
	require.Equal(t, id.RoomID(testStreamRoomID+"-1"), streams.pendingSubscribe[0].key.roomID)
}

func TestHelperCloseCancelsSubscriptions(t *testing.T) {
	ts, _ := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, "RECEIVER")
	streams := newTestHelper(t, client)

	require.NoError(t, streams.Subscribe(context.Background(), testStreamRoomID, testStreamEventID, newTestDescriptor(false)))
	require.Len(t, streams.subscriptions, 1)

	require.NoError(t, streams.Close())
	require.True(t, streams.closed.Load())
	require.Empty(t, streams.subscriptions)
	require.Error(t, streams.Subscribe(context.Background(), testStreamRoomID, testStreamEventID, newTestDescriptor(false)))
}

func TestDecryptLogicalEventRejectsInvalidIV(t *testing.T) {
	descriptor := newTestDescriptor(true)
	content, err := newUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello"))
	require.NoError(t, err)
	raw, err := rawMapFromContent(content)
	require.NoError(t, err)
	payload, err := json.Marshal(removeStreamRouting(raw))
	require.NoError(t, err)
	encrypted, err := encryptLogicalEvent(event.ToDeviceBeeperStreamUpdate, payload, testStreamRoomID, testStreamEventID, descriptor.Encryption.Key)
	require.NoError(t, err)

	encrypted.IV = "invalid"
	_, _, err = decryptLogicalEvent(encrypted, descriptor.Encryption.Key)
	require.Error(t, err)
}
