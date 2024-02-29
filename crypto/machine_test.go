// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
)

type mockStateStore struct{}

func (mockStateStore) IsEncrypted(context.Context, id.RoomID) (bool, error) {
	return true, nil
}

func (mockStateStore) GetEncryptionEvent(context.Context, id.RoomID) (*event.EncryptionEventContent, error) {
	return &event.EncryptionEventContent{
		RotationPeriodMessages: 3,
	}, nil
}

func (mockStateStore) FindSharedRooms(context.Context, id.UserID) ([]id.RoomID, error) {
	return []id.RoomID{"room1"}, nil
}

func newMachine(t *testing.T, userID id.UserID) *OlmMachine {
	client, err := mautrix.NewClient("http://localhost", userID, "token")
	if err != nil {
		t.Fatalf("Error creating client: %v", err)
	}
	client.DeviceID = "device1"

	gobStore := NewMemoryStore(nil)
	if err != nil {
		t.Fatalf("Error creating Gob store: %v", err)
	}

	machine := NewOlmMachine(client, nil, gobStore, mockStateStore{})
	if err := machine.Load(context.TODO()); err != nil {
		t.Fatalf("Error creating account: %v", err)
	}

	return machine
}

func TestRatchetMegolmSession(t *testing.T) {
	mach := newMachine(t, "user1")
	outSess := mach.newOutboundGroupSession(context.TODO(), "meow")
	inSess, err := mach.CryptoStore.GetGroupSession(context.TODO(), "meow", mach.OwnIdentity().IdentityKey, outSess.ID())
	require.NoError(t, err)
	assert.Equal(t, uint32(0), inSess.Internal.FirstKnownIndex())
	err = inSess.RatchetTo(10)
	assert.NoError(t, err)
	assert.Equal(t, uint32(10), inSess.Internal.FirstKnownIndex())
}

func TestOlmMachineOlmMegolmSessions(t *testing.T) {
	machineOut := newMachine(t, "user1")
	machineIn := newMachine(t, "user2")

	// generate OTKs for receiving machine
	otks := machineIn.account.getOneTimeKeys("user2", "device2", 0)
	var otk mautrix.OneTimeKey
	for _, otkTmp := range otks {
		// take first OTK
		otk = otkTmp
		break
	}

	// create outbound olm session for sending machine using OTK
	olmSession, err := machineOut.account.Internal.NewOutboundSession(machineIn.account.IdentityKey(), otk.Key)
	if err != nil {
		t.Errorf("Failed to create outbound olm session: %v", err)
	}

	// store sender device identity in receiving machine store
	machineIn.CryptoStore.PutDevices(context.TODO(), "user1", map[id.DeviceID]*id.Device{
		"device1": {
			UserID:      "user1",
			DeviceID:    "device1",
			IdentityKey: machineOut.account.IdentityKey(),
			SigningKey:  machineOut.account.SigningKey(),
		},
	})

	// create & store outbound megolm session for sending the event later
	megolmOutSession := machineOut.newOutboundGroupSession(context.TODO(), "room1")
	megolmOutSession.Shared = true
	machineOut.CryptoStore.AddOutboundGroupSession(context.TODO(), megolmOutSession)

	// encrypt m.room_key event with olm session
	deviceIdentity := &id.Device{
		UserID:      "user2",
		DeviceID:    "device2",
		IdentityKey: machineIn.account.IdentityKey(),
		SigningKey:  machineIn.account.SigningKey(),
	}
	wrapped := wrapSession(olmSession)
	content := machineOut.encryptOlmEvent(context.TODO(), wrapped, deviceIdentity, event.ToDeviceRoomKey, megolmOutSession.ShareContent())

	senderKey := machineOut.account.IdentityKey()
	signingKey := machineOut.account.SigningKey()

	for _, content := range content.OlmCiphertext {
		// decrypt olm ciphertext
		decrypted, err := machineIn.decryptAndParseOlmCiphertext(context.TODO(), &event.Event{
			Type:   event.ToDeviceEncrypted,
			Sender: "user1",
		}, senderKey, content.Type, content.Body)
		if err != nil {
			t.Errorf("Error decrypting olm content: %v", err)
		}
		// store room key in new inbound group session
		roomKeyEvt := decrypted.Content.AsRoomKey()
		igs, err := NewInboundGroupSession(senderKey, signingKey, "room1", roomKeyEvt.SessionKey, 0, 0, false)
		if err != nil {
			t.Errorf("Error creating inbound megolm session: %v", err)
		}
		if err = machineIn.CryptoStore.PutGroupSession(context.TODO(), "room1", senderKey, igs.ID(), igs); err != nil {
			t.Errorf("Error storing inbound megolm session: %v", err)
		}
	}

	// encrypt event with megolm session in sending machine
	eventContent := map[string]string{"hello": "world"}
	encryptedEvtContent, err := machineOut.EncryptMegolmEvent(context.TODO(), "room1", event.EventMessage, eventContent)
	if err != nil {
		t.Errorf("Error encrypting megolm event: %v", err)
	}
	if megolmOutSession.MessageCount != 1 {
		t.Errorf("Megolm outbound session message count is not 1 but %d", megolmOutSession.MessageCount)
	}

	encryptedEvt := &event.Event{
		Content: event.Content{Parsed: encryptedEvtContent},
		Type:    event.EventEncrypted,
		ID:      "event1",
		RoomID:  "room1",
		Sender:  "user1",
	}

	// decrypt event on receiving machine and confirm
	decryptedEvt, err := machineIn.DecryptMegolmEvent(context.TODO(), encryptedEvt)
	if err != nil {
		t.Errorf("Error decrypting megolm event: %v", err)
	}
	if decryptedEvt.Type != event.EventMessage {
		t.Errorf("Expected event type %v, got %v", event.EventMessage, decryptedEvt.Type)
	}
	if decryptedEvt.Content.Raw["hello"] != "world" {
		t.Errorf("Expected event content %v, got %v", eventContent, decryptedEvt.Content.Raw)
	}

	machineOut.EncryptMegolmEvent(context.TODO(), "room1", event.EventMessage, eventContent)
	if megolmOutSession.Expired() {
		t.Error("Megolm outbound session expired before 3rd message")
	}
	machineOut.EncryptMegolmEvent(context.TODO(), "room1", event.EventMessage, eventContent)
	if !megolmOutSession.Expired() {
		t.Error("Megolm outbound session not expired after 3rd message")
	}
}
