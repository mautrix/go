package mautrix

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func TestBeeperStreamReceiverHandleTimelineEventSubscribes(t *testing.T) {
	ts, recorder := newSendToDeviceRecorderServer(t)
	client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, testStreamSubscriberDev)
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

	assertTestStreamSubscribe(t, recorder, testStreamBotUserID, testStreamBotDeviceID)
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

func TestBeeperStreamReceiverUpdateCallback(t *testing.T) {
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

			if consumed := receiver.HandleToDeviceEvent(context.Background(), evt); !consumed {
				t.Fatal("expected update to be consumed")
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
		})
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
	evt := newTestReceiverUpdateEvent(t, receiver, true, makeStreamID())

	consumed := receiver.HandleToDeviceEvent(context.Background(), evt)
	if !consumed {
		t.Fatal("expected encrypted update to be consumed")
	}
	if called {
		t.Fatal("expected mismatched encrypted update to be ignored")
	}
}

func newTestReceiverUpdateEvent(t *testing.T, receiver *BeeperStreamReceiver, encrypted bool, eventStreamID string) *event.Event {
	t.Helper()
	sub := &beeperStreamSubscription{
		key: beeperStreamKey{roomID: testStreamRoomID, eventID: testStreamEventID},
		descriptor: &event.BeeperStreamInfo{
			UserID:   testStreamBotUserID,
			DeviceID: testStreamBotDeviceID,
			Type:     testStreamType,
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

	content, err := newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello"))
	if err != nil {
		t.Fatalf("newStreamUpdateContent returned error: %v", err)
	}
	if !encrypted {
		return &event.Event{
			Sender:  testStreamBotUserID,
			Type:    event.ToDeviceBeeperStreamUpdate,
			Content: *content,
		}
	}

	encryptedContent, err := EncryptBeeperStreamEvent(event.ToDeviceBeeperStreamUpdate, content, eventStreamID, encKey)
	if err != nil {
		t.Fatalf("EncryptBeeperStreamEvent returned error: %v", err)
	}
	return &event.Event{
		Sender:  testStreamBotUserID,
		Type:    event.ToDeviceEncrypted,
		Content: event.Content{Parsed: encryptedContent},
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
