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

			require.True(t, ShouldInterceptToDeviceEvent(context.Background(), receiver.HandleToDeviceEvent, evt))

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
