// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

type Logger interface {
	Error(message string, args ...interface{})
	Warn(message string, args ...interface{})
	Debug(message string, args ...interface{})
	Trace(message string, args ...interface{})
}

type OlmMachine struct {
	client *mautrix.Client
	store  Store

	account *OlmAccount
	log     Logger
}

func NewOlmMachine(client *mautrix.Client, log Logger, store Store) *OlmMachine {
	return &OlmMachine{
		client: client,
		log:    log,
		store:  store,
	}
}

func (mach *OlmMachine) Load() (err error) {
	mach.account, err = mach.store.GetAccount()
	if err != nil {
		return
	}
	if mach.account == nil {
		mach.account = &OlmAccount{
			Account: *olm.NewAccount(),
		}
	}
	return nil
}

func (mach *OlmMachine) SaveAccount() {
	err := mach.store.PutAccount(mach.account)
	if err != nil {
		mach.log.Error("Failed to save account: %v", err)
	}
}

func (mach *OlmMachine) ProcessSyncResponse(resp *mautrix.RespSync, since string) {
	if len(resp.DeviceLists.Changed) > 0 {
		mach.FetchKeys(resp.DeviceLists.Changed, since)
	}

	for _, evt := range resp.ToDevice.Events {
		mach.log.Trace("Got to-device event %s from %s", evt.Type.Type, evt.Sender)
		evt.Type.Class = event.ToDeviceEventType
		err := evt.Content.ParseRaw(evt.Type)
		if err != nil {
			mach.log.Warn("Failed to parse to-device event of type %s: %v", evt.Type.Type, err)
			continue
		}
		mach.HandleToDeviceEvent(evt)
	}

	min := mach.account.MaxNumberOfOneTimeKeys() / 2
	if resp.DeviceOneTimeKeysCount.SignedCurve25519 <= int(min) {
		mach.log.Trace("Sync response said we have %d signed curve25519 keys left, sharing new ones...", resp.DeviceOneTimeKeysCount.SignedCurve25519)
		err := mach.ShareKeys()
		if err != nil {
			mach.log.Error("Failed to share keys: %v", err)
		}
	}
}

func (mach *OlmMachine) HandleToDeviceEvent(evt *event.Event) {
	switch evt.Content.Parsed.(type) {
	case *event.EncryptedEventContent:
		decryptedEvt, err := mach.decryptOlmEvent(evt)
		if err != nil {
			mach.log.Error("Failed to decrypt to-device event: %v", err)
			return
		}
		switch content := decryptedEvt.Content.Parsed.(type) {
		case *event.RoomKeyEventContent:
			mach.receiveRoomKey(decryptedEvt, content)
			// TODO handle other encrypted to-device events
		}
		// TODO handle other unencrypted to-device events. At least m.room_key_request and m.verification.start
	}
}

func (mach *OlmMachine) createGroupSession(senderKey id.SenderKey, signingKey id.Ed25519, roomID id.RoomID, sessionID id.SessionID, sessionKey string) {
	igs, err := NewInboundGroupSession(senderKey, signingKey, roomID, sessionKey)
	if err != nil {
		mach.log.Error("Failed to create inbound group session: %v", err)
		return
	} else if igs.ID() != sessionID {
		mach.log.Warn("Mismatched session ID while creating inbound group session")
		return
	}
	err = mach.store.PutGroupSession(roomID, senderKey, sessionID, igs)
	if err != nil {
		mach.log.Error("Failed to store new inbound group session: %v", err)
	}
	mach.log.Trace("Created inbound group session %s/%s/%s", roomID, senderKey, sessionID)
}

func (mach *OlmMachine) receiveRoomKey(evt *OlmEvent, content *event.RoomKeyEventContent) {
	// TODO nio had a comment saying "handle this better" for the case where evt.Keys.Ed25519 is none?
	if content.Algorithm != id.AlgorithmMegolmV1 || evt.Keys.Ed25519 == "" {
		return
	}

	mach.createGroupSession(evt.SenderKey, evt.Keys.Ed25519, content.RoomID, content.SessionID, content.SessionKey)
}

// ShareKeys returns a key upload request.
func (mach *OlmMachine) ShareKeys() error {
	var deviceKeys *mautrix.DeviceKeys
	if !mach.account.Shared {
		deviceKeys = mach.account.getInitialKeys(mach.client.UserID, mach.client.DeviceID)
		mach.log.Trace("Going to upload initial account keys")
	}
	oneTimeKeys := mach.account.getOneTimeKeys(mach.client.UserID, mach.client.DeviceID)
	if len(oneTimeKeys) == 0 && deviceKeys == nil {
		mach.log.Trace("No one-time keys nor device keys got when trying to share keys")
		return nil
	}
	req := &mautrix.ReqUploadKeys{
		DeviceKeys:  deviceKeys,
		OneTimeKeys: oneTimeKeys,
	}
	mach.log.Trace("Uploading %d one-time keys:\n%s", len(oneTimeKeys))
	_, err := mach.client.UploadKeys(req)
	if err != nil {
		return err
	}
	mach.account.Shared = true
	mach.SaveAccount()
	mach.log.Trace("Shared keys and saved account")
	return nil
}
