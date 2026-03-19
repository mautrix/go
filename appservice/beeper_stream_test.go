// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	testBotRoomID     = "!room:example.com"
	testBotEventID    = "$event"
	testBotSubscriber = "@alice:example.com"
	testBotSubDevice  = "SUBDEVICE"
)

func newTestAppService() *AppService {
	as := Create()
	as.HomeserverDomain = "example.com"
	as.Registration = &Registration{
		AppToken:        "app-token",
		SenderLocalpart: "bot",
	}
	return as
}

func deliverTestBotSubscribe(t *testing.T, as *AppService, deviceID id.DeviceID) {
	t.Helper()
	as.handleEvents(context.Background(), []*event.Event{{
		Sender:     testBotSubscriber,
		ToUserID:   as.BotMXID(),
		ToDeviceID: deviceID,
		Type:       event.ToDeviceBeeperStreamSubscribe,
		Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
			RoomID:   testBotRoomID,
			EventID:  testBotEventID,
			DeviceID: testBotSubDevice,
			ExpiryMS: 60_000,
		}},
	}}, event.ToDeviceEventType)
}

func TestHandleTransactionDispatchesToDeviceWithoutEphemeralFlag(t *testing.T) {
	as := newTestAppService()
	as.Registration.EphemeralEvents = false

	as.handleTransaction(context.Background(), "txn1", &Transaction{
		ToDeviceEvents: []*event.Event{{
			Sender:     testBotSubscriber,
			ToUserID:   as.BotMXID(),
			ToDeviceID: testBotSubDevice,
			Type:       event.ToDeviceBeeperStreamSubscribe,
			Content: event.Content{Parsed: &event.BeeperStreamSubscribeEventContent{
				RoomID:   testBotRoomID,
				EventID:  testBotEventID,
				DeviceID: testBotSubDevice,
				ExpiryMS: 60_000,
			}},
		}},
	})

	select {
	case evt := <-as.ToDeviceEvents:
		require.Equal(t, event.ToDeviceBeeperStreamSubscribe, evt.Type)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for to-device event")
	}
}

func TestEventProcessorReceivesBeeperStreamToDeviceEvents(t *testing.T) {
	as := newTestAppService()
	ep := NewEventProcessor(as)
	ep.ExecMode = Sync
	received := make(chan *event.Event, 1)
	ep.On(event.ToDeviceBeeperStreamSubscribe, func(_ context.Context, evt *event.Event) {
		received <- evt
	})
	ep.Start(context.Background())
	defer ep.Stop()

	deliverTestBotSubscribe(t, as, testBotSubDevice)

	select {
	case evt := <-received:
		require.Equal(t, event.ToDeviceBeeperStreamSubscribe, evt.Type)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event processor delivery")
	}
}
