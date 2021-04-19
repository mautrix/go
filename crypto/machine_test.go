// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"os"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type emptyLogger struct{}

func (emptyLogger) Error(message string, args ...interface{}) {}
func (emptyLogger) Warn(message string, args ...interface{})  {}
func (emptyLogger) Debug(message string, args ...interface{}) {}
func (emptyLogger) Trace(message string, args ...interface{}) {}

type mockStateStore struct{}

func (mockStateStore) IsEncrypted(id.RoomID) bool {
	return true
}

func (mockStateStore) GetEncryptionEvent(id.RoomID) *event.EncryptionEventContent {
	return &event.EncryptionEventContent{
		RotationPeriodMessages: 3,
	}
}

func (mockStateStore) FindSharedRooms(id.UserID) []id.RoomID {
	return []id.RoomID{"room1"}
}

func newMachine(t *testing.T, userID id.UserID) (*OlmMachine, string) {
	client, err := mautrix.NewClient("http://localhost", userID, "token")
	if err != nil {
		t.Fatalf("Error creating client: %v", err)
	}
	client.DeviceID = "device1"

	storeFileName := "gob_store_test_" + userID.String() + ".gob"
	gobStore, err := NewGobStore(storeFileName)
	if err != nil {
		os.Remove(storeFileName)
		t.Fatalf("Error creating Gob store: %v", err)
	}

	machine := NewOlmMachine(client, emptyLogger{}, gobStore, mockStateStore{})
	if err := machine.Load(); err != nil {
		os.Remove(storeFileName)
		t.Fatalf("Error creating account: %v", err)
	}

	return machine, storeFileName
}

func TestOlmMachineOlmMegolmSessions(t *testing.T) {
	machineOut, storeFileNameOut := newMachine(t, "user1")
	defer os.Remove(storeFileNameOut)
	machineIn, storeFileNameIn := newMachine(t, "user2")
	defer os.Remove(storeFileNameIn)

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
	machineIn.CryptoStore.PutDevices("user1", map[id.DeviceID]*DeviceIdentity{
		"device1": {
			UserID:      "user1",
			DeviceID:    "device1",
			IdentityKey: machineOut.account.IdentityKey(),
			SigningKey:  machineOut.account.SigningKey(),
		},
	})

	// create & store outbound megolm session for sending the event later
	megolmOutSession := machineOut.newOutboundGroupSession("room1")
	megolmOutSession.Shared = true
	machineOut.CryptoStore.AddOutboundGroupSession(megolmOutSession)

	// encrypt m.room_key event with olm session
	deviceIdentity := &DeviceIdentity{
		UserID:      "user2",
		DeviceID:    "device2",
		IdentityKey: machineIn.account.IdentityKey(),
		SigningKey:  machineIn.account.SigningKey(),
	}
	wrapped := wrapSession(olmSession)
	content := machineOut.encryptOlmEvent(wrapped, deviceIdentity, event.ToDeviceRoomKey, megolmOutSession.ShareContent())

	senderKey := machineOut.account.IdentityKey()
	signingKey := machineOut.account.SigningKey()

	for _, content := range content.OlmCiphertext {
		// decrypt olm ciphertext
		decrypted, err := machineIn.decryptAndParseOlmCiphertext("user1", "device1", senderKey, content.Type, content.Body)
		if err != nil {
			t.Errorf("Error decrypting olm content: %v", err)
		}
		// store room key in new inbound group session
		decrypted.Content.ParseRaw(event.ToDeviceRoomKey)
		roomKeyEvt := decrypted.Content.AsRoomKey()
		igs, err := NewInboundGroupSession(senderKey, signingKey, "room1", roomKeyEvt.SessionKey)
		if err != nil {
			t.Errorf("Error creating inbound megolm session: %v", err)
		}
		if err = machineIn.CryptoStore.PutGroupSession("room1", senderKey, igs.ID(), igs); err != nil {
			t.Errorf("Error storing inbound megolm session: %v", err)
		}
	}

	// encrypt event with megolm session in sending machine
	eventContent := map[string]string{"hello": "world"}
	encryptedEvtContent, err := machineOut.EncryptMegolmEvent("room1", event.EventMessage, eventContent)
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
	decryptedEvt, err := machineIn.DecryptMegolmEvent(encryptedEvt)
	if err != nil {
		t.Errorf("Error decrypting megolm event: %v", err)
	}
	if decryptedEvt.Type != event.EventMessage {
		t.Errorf("Expected event type %v, got %v", event.EventMessage, decryptedEvt.Type)
	}
	if decryptedEvt.Content.Raw["hello"] != "world" {
		t.Errorf("Expected event content %v, got %v", eventContent, decryptedEvt.Content.Raw)
	}

	machineOut.EncryptMegolmEvent("room1", event.EventMessage, eventContent)
	if megolmOutSession.Expired() {
		t.Error("Megolm outbound session expired before 3rd message")
	}
	machineOut.EncryptMegolmEvent("room1", event.EventMessage, eventContent)
	if !megolmOutSession.Expired() {
		t.Error("Megolm outbound session not expired after 3rd message")
	}
}
