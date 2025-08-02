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

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
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
	require.NoError(t, err, "Error creating client")
	client.DeviceID = "device1"

	gobStore := NewMemoryStore(nil)
	require.NoError(t, err, "Error creating Gob store")

	machine := NewOlmMachine(client, nil, gobStore, mockStateStore{})
	err = machine.Load(context.TODO())
	require.NoError(t, err, "Error creating account")

	return machine
}

func TestRatchetMegolmSession(t *testing.T) {
	mach := newMachine(t, "user1")
	outSess, err := mach.newOutboundGroupSession(context.TODO(), "meow")
	assert.NoError(t, err)
	inSess, err := mach.CryptoStore.GetGroupSession(context.TODO(), "meow", outSess.ID())
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
	machineIn.account.Internal.MarkKeysAsPublished()

	// create outbound olm session for sending machine using OTK
	olmSession, err := machineOut.account.Internal.NewOutboundSession(machineIn.account.IdentityKey(), otk.Key)
	require.NoError(t, err, "Error creating outbound olm session")

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
	megolmOutSession, err := machineOut.newOutboundGroupSession(context.TODO(), "room1")
	assert.NoError(t, err)
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
		require.NoError(t, err, "Error decrypting olm ciphertext")

		// store room key in new inbound group session
		roomKeyEvt := decrypted.Content.AsRoomKey()
		igs, err := NewInboundGroupSession(senderKey, signingKey, "room1", roomKeyEvt.SessionKey, 0, 0, false)
		require.NoError(t, err, "Error creating inbound group session")
		err = machineIn.CryptoStore.PutGroupSession(context.TODO(), igs)
		require.NoError(t, err, "Error storing inbound group session")
	}

	// encrypt event with megolm session in sending machine
	eventContent := map[string]string{"hello": "world"}
	encryptedEvtContent, err := machineOut.EncryptMegolmEvent(context.TODO(), "room1", event.EventMessage, eventContent)
	require.NoError(t, err, "Error encrypting megolm event")
	assert.Equal(t, 1, megolmOutSession.MessageCount)

	encryptedEvt := &event.Event{
		Content: event.Content{Parsed: encryptedEvtContent},
		Type:    event.EventEncrypted,
		ID:      "event1",
		RoomID:  "room1",
		Sender:  "user1",
	}

	// decrypt event on receiving machine and confirm
	decryptedEvt, err := machineIn.DecryptMegolmEvent(context.TODO(), encryptedEvt)
	require.NoError(t, err, "Error decrypting megolm event")
	assert.Equal(t, event.EventMessage, decryptedEvt.Type)
	assert.Equal(t, "world", decryptedEvt.Content.Raw["hello"])

	machineOut.EncryptMegolmEvent(context.TODO(), "room1", event.EventMessage, eventContent)
	assert.False(t, megolmOutSession.Expired(), "Megolm outbound session expired before 3rd message")
	machineOut.EncryptMegolmEvent(context.TODO(), "room1", event.EventMessage, eventContent)
	assert.True(t, megolmOutSession.Expired(), "Megolm outbound session not expired after 3rd message")
}
