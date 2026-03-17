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
			ts, _ := newSendToDeviceRecorderServer(t)
			received := make(chan *BeeperStreamUpdate, 1)
			client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, "RECEIVER")
			receiver := client.GetOrCreateBeeperStreamReceiver(&BeeperStreamReceiverOptions{
				OnUpdate: func(_ context.Context, update *BeeperStreamUpdate) error {
					received <- update
					return nil
				},
			})
			t.Cleanup(receiver.Stop)

			descriptor := newTestReceiverDescriptor(tc.encrypted)
			require.NoError(t, receiver.EnsureSubscription(context.Background(), testStreamRoomID, testStreamEventID, descriptor))

			evt := newTestReceiverUpdateEvent(t, descriptor, "")
			require.True(t, client.HandleToDeviceEvent(context.Background(), evt))

			select {
			case update := <-received:
				updateContent, err := json.Marshal(update.Content)
				require.NoError(t, err)
				require.Equal(t, testStreamBotUserID, update.Sender)
				require.Equal(t, testStreamRoomID, update.RoomID)
				require.Equal(t, testStreamEventID, update.EventID)
				assertStreamUpdateMap(t, decodeJSONMap(t, updateContent))
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for update callback")
			}
		})
	}
}

func TestBeeperStreamReceiverIgnoresWrongEncryptedStreamID(t *testing.T) {
	ts, _ := newSendToDeviceRecorderServer(t)
	var called bool
	client := newTestStreamClient(t, ts.URL, testStreamSubscriberID, "RECEIVER")
	receiver := client.GetOrCreateBeeperStreamReceiver(&BeeperStreamReceiverOptions{
		OnUpdate: func(_ context.Context, _ *BeeperStreamUpdate) error {
			called = true
			return nil
		},
	})
	t.Cleanup(receiver.Stop)

	descriptor := newTestReceiverDescriptor(true)
	require.NoError(t, receiver.EnsureSubscription(context.Background(), testStreamRoomID, testStreamEventID, descriptor))

	evt := newTestReceiverUpdateEvent(t, descriptor, makeStreamID())
	require.True(t, client.HandleToDeviceEvent(context.Background(), evt))
	require.False(t, called)
}

func newTestReceiverDescriptor(encrypted bool) *event.BeeperStreamInfo {
	descriptor := &event.BeeperStreamInfo{
		UserID: testStreamBotUserID,
		Type:   testStreamType,
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

func newTestReceiverUpdateEvent(t *testing.T, descriptor *event.BeeperStreamInfo, eventStreamID id.StreamID) *event.Event {
	t.Helper()

	content, err := newStreamUpdateContent(testStreamRoomID, testStreamEventID, newTestPublishContent("hello"))
	require.NoError(t, err)
	if descriptor.Encryption == nil {
		var wireContent event.Content
		data, err := json.Marshal(content)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &wireContent))
		return &event.Event{
			Sender:  testStreamBotUserID,
			Type:    event.ToDeviceBeeperStreamUpdate,
			Content: wireContent,
		}
	}

	if eventStreamID == "" {
		eventStreamID = descriptor.Encryption.StreamID
	}
	encryptedContent, err := encryptBeeperStreamEvent(event.ToDeviceBeeperStreamUpdate, content, eventStreamID, descriptor.Encryption.Key)
	require.NoError(t, err)
	return &event.Event{
		Sender:  testStreamBotUserID,
		Type:    event.ToDeviceEncrypted,
		Content: event.Content{Parsed: encryptedContent},
	}
}
