package mautrix

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func newTestBeeperStreamInfo() *event.BeeperStreamInfo {
	return &event.BeeperStreamInfo{UserID: testStreamBotUserID, Type: testStreamType, ExpiryMS: 60_000}
}

func newTestReceiverOptions() *BeeperStreamReceiverOptions {
	return &BeeperStreamReceiverOptions{DefaultExpiry: time.Minute, MinimumRenewInterval: time.Hour}
}

func TestBeeperStreamReceiverHandleTimelineEvent(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, testStreamSubscriberDev)

	// valid descriptor triggers subscribe
	receiver := client.GetOrCreateBeeperStreamReceiver(newTestReceiverOptions())
	receiver.HandleTimelineEvent(context.Background(), &event.Event{
		ID:     testStreamEventID,
		RoomID: testStreamRoomID,
		Type:   event.EventMessage,
		Content: event.Content{Parsed: &event.MessageEventContent{
			MsgType:      event.MsgText,
			Body:         "Pondering...",
			BeeperStream: newTestBeeperStreamInfo(),
		}},
	})
	defer receiver.StopSubscription(testStreamRoomID, testStreamEventID)
	assertTestStreamSubscribe(t, recorder, testStreamBotUserID, "*")

	// unsupported encryption algorithm: no subscribe, no subscription created
	receiver2 := NewBeeperStreamReceiver(client, newTestReceiverOptions())
	defer receiver2.Stop()
	receiver2.HandleTimelineEvent(context.Background(), &event.Event{
		ID:     testStreamEventID,
		RoomID: testStreamRoomID,
		Type:   event.EventMessage,
		Content: event.Content{Parsed: &event.MessageEventContent{
			MsgType: event.MsgText,
			Body:    "Pondering...",
			BeeperStream: &event.BeeperStreamInfo{
				UserID: testStreamBotUserID,
				Type:   testStreamType,
				Encryption: &event.BeeperStreamEncryptionInfo{
					Algorithm: id.AlgorithmMegolmV1,
					Key:       makeStreamKey(),
					StreamID:  makeStreamID(),
				},
			},
		}},
	})
	require.NotContains(t, receiver2.subscriptions, beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID})
	select {
	case req := <-recorder.requests:
		t.Fatalf("unexpected subscribe request: %s", req.path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBeeperStreamReceiverEnsureSubscription(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, testStreamSubscriberDev)

	// cancelled caller context doesn't prevent subscription
	receiver := client.GetOrCreateBeeperStreamReceiver(newTestReceiverOptions())
	defer receiver.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, receiver.EnsureSubscription(ctx, testStreamRoomID, testStreamEventID, newTestBeeperStreamInfo()))
	assertTestStreamSubscribe(t, recorder, testStreamBotUserID, "*")

	// unsupported encryption algorithm rejected
	receiver2 := NewBeeperStreamReceiver(&Client{UserID: testStreamSubscriberID, DeviceID: testStreamSubscriberDev}, nil)
	require.Error(t, receiver2.EnsureSubscription(context.Background(), testStreamRoomID, testStreamEventID, &event.BeeperStreamInfo{
		UserID: testStreamBotUserID,
		Type:   testStreamType,
		Encryption: &event.BeeperStreamEncryptionInfo{
			Algorithm: id.AlgorithmMegolmV1,
			Key:       makeStreamKey(),
			StreamID:  makeStreamID(),
		},
	}))
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

	require.NotContains(t, receiver.subscriptions, beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID})
	require.Error(t, ctx.Err(), "expected subscription cancel to be called")
}

func TestBeeperStreamReceiverUpdate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		encrypted bool
	}{
		{name: "plain", encrypted: false},
		{name: "encrypted", encrypted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan *BeeperStreamUpdate, 1)
			receiver := NewBeeperStreamReceiver(nil, &BeeperStreamReceiverOptions{
				OnUpdate: func(_ context.Context, update *BeeperStreamUpdate) error {
					received <- update
					return nil
				},
			})
			evt := newTestReceiverUpdateEvent(t, receiver, tc.encrypted, "")

			require.True(t, receiver.HandleToDeviceEvent(context.Background(), evt))

			select {
			case update := <-received:
				require.Equal(t, testStreamBotUserID, update.Sender)
				require.Equal(t, testStreamRoomID, update.RoomID)
				require.Equal(t, testStreamEventID, update.EventID)
				assertStreamUpdateMap(t, decodeJSONMap(t, must(json.Marshal(update.Content))))
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for update callback")
			}
		})
	}

	// encrypted update with wrong stream_id is ignored
	var called bool
	receiver := NewBeeperStreamReceiver(nil, &BeeperStreamReceiverOptions{
		OnUpdate: func(_ context.Context, _ *BeeperStreamUpdate) error {
			called = true
			return nil
		},
	})
	evt := newTestReceiverUpdateEvent(t, receiver, true, makeStreamID())
	require.True(t, receiver.HandleToDeviceEvent(context.Background(), evt))
	require.False(t, called)
}

func newTestReceiverUpdateEvent(t *testing.T, receiver *BeeperStreamReceiver, encrypted bool, eventStreamID string) *event.Event {
	t.Helper()
	sub := &beeperStreamSubscription{
		key: beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID},
		descriptor: &event.BeeperStreamInfo{
			UserID: testStreamBotUserID,
			Type:   testStreamType,
		},
		cancel: func() {},
	}
	encKey := ""
	if encrypted {
		encKey = makeStreamKey()
		streamID := makeStreamID()
		sub.descriptor.Encryption = &event.BeeperStreamEncryptionInfo{
			Algorithm: id.AlgorithmBeeperStreamAESGCM,
			Key:       encKey,
			StreamID:  streamID,
		}
		receiver.subscriptionsByStreamID[streamID] = sub
		if eventStreamID == "" {
			eventStreamID = streamID
		}
	}
	receiver.subscriptions[sub.key] = sub

	content := must(newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello")))
	if !encrypted {
		// Round-trip through JSON to populate VeryRaw, which ParseRaw depends on.
		var wireContent event.Content
		require.NoError(t, json.Unmarshal(must(json.Marshal(content)), &wireContent))
		return &event.Event{
			Sender:  testStreamBotUserID,
			Type:    event.ToDeviceBeeperStreamUpdate,
			Content: wireContent,
		}
	}

	encryptedContent := must(EncryptBeeperStreamEvent(event.ToDeviceBeeperStreamUpdate, content, eventStreamID, encKey))
	return &event.Event{
		Sender:  testStreamBotUserID,
		Type:    event.ToDeviceEncrypted,
		Content: event.Content{Parsed: encryptedContent},
	}
}
