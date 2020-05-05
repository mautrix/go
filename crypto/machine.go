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
	Client *mautrix.Client
	Log    Logger

	CryptoStore Store
	StateStore  StateStore

	account *OlmAccount
}

type StateStore interface {
	IsEncrypted(id.RoomID) bool
	FindSharedRooms(id.UserID) []id.RoomID
}

func NewOlmMachine(client *mautrix.Client, log Logger, cryptoStore Store, stateStore StateStore) *OlmMachine {
	return &OlmMachine{
		Client:      client,
		Log:         log,
		CryptoStore: cryptoStore,
		StateStore:  stateStore,
	}
}

func (mach *OlmMachine) Load() (err error) {
	mach.account, err = mach.CryptoStore.GetAccount()
	if err != nil {
		return
	}
	if mach.account == nil {
		mach.account = &OlmAccount{
			Internal: *olm.NewAccount(),
		}
	}
	return nil
}

func (mach *OlmMachine) SaveAccount() {
	err := mach.CryptoStore.PutAccount(mach.account)
	if err != nil {
		mach.Log.Error("Failed to save account: %v", err)
	}
}

func (mach *OlmMachine) FlushStore() error {
	return mach.CryptoStore.Flush()
}

func (mach *OlmMachine) ProcessSyncResponse(resp *mautrix.RespSync, since string) {
	if len(resp.DeviceLists.Changed) > 0 {
		mach.Log.Trace("Device list changes in /sync: %v", resp.DeviceLists.Changed)
		mach.fetchKeys(resp.DeviceLists.Changed, since)
	}

	for _, evt := range resp.ToDevice.Events {
		mach.Log.Trace("Got to-device event %s from %s", evt.Type.Type, evt.Sender)
		evt.Type.Class = event.ToDeviceEventType
		err := evt.Content.ParseRaw(evt.Type)
		if err != nil {
			mach.Log.Warn("Failed to parse to-device event of type %s: %v", evt.Type.Type, err)
			continue
		}
		mach.HandleToDeviceEvent(evt)
	}

	min := mach.account.Internal.MaxNumberOfOneTimeKeys() / 2
	if resp.DeviceOneTimeKeysCount.SignedCurve25519 <= int(min) {
		mach.Log.Trace("Sync response said we have %d signed curve25519 keys left, sharing new ones...", resp.DeviceOneTimeKeysCount.SignedCurve25519)
		err := mach.ShareKeys()
		if err != nil {
			mach.Log.Error("Failed to share keys: %v", err)
		}
	}
}

func (mach *OlmMachine) HandleMemberEvent(evt *event.Event) {
	content := evt.Content.AsMember()
	if content == nil {
		return
	}
	var prevContent *event.MemberEventContent
	if evt.Unsigned.PrevContent != nil {
		_ = evt.Unsigned.PrevContent.ParseRaw(evt.Type)
		prevContent = evt.Unsigned.PrevContent.AsMember()
	}
	if prevContent == nil {
		prevContent = &event.MemberEventContent{Membership: "unknown"}
	}
	if prevContent.Membership == content.Membership ||
		(prevContent.Membership == event.MembershipInvite && content.Membership == event.MembershipJoin) ||
		(prevContent.Membership == event.MembershipBan && content.Membership == event.MembershipLeave) ||
		(prevContent.Membership == event.MembershipLeave && content.Membership == event.MembershipBan) {
		return
	}
	mach.Log.Trace("Got membership state event in %s changing %s from %s to %s, invalidating group session", evt.RoomID, evt.GetStateKey(), prevContent.Membership, content.Membership)
	err := mach.CryptoStore.PopOutboundGroupSession(evt.RoomID)
	if err != nil {
		mach.Log.Warn("Failed to invalidate outbound group session of %s: %v", evt.RoomID, err)
	}
}

func (mach *OlmMachine) HandleToDeviceEvent(evt *event.Event) {
	switch evt.Content.Parsed.(type) {
	case *event.EncryptedEventContent:
		decryptedEvt, err := mach.decryptOlmEvent(evt)
		if err != nil {
			mach.Log.Error("Failed to decrypt to-device event: %v", err)
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
		mach.Log.Error("Failed to create inbound group session: %v", err)
		return
	} else if igs.ID() != sessionID {
		mach.Log.Warn("Mismatched session ID while creating inbound group session")
		return
	}
	err = mach.CryptoStore.PutGroupSession(roomID, senderKey, sessionID, igs)
	if err != nil {
		mach.Log.Error("Failed to store new inbound group session: %v", err)
	}
	mach.Log.Trace("Created inbound group session %s/%s/%s", roomID, senderKey, sessionID)
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
		deviceKeys = mach.account.getInitialKeys(mach.Client.UserID, mach.Client.DeviceID)
		mach.Log.Trace("Going to upload initial account keys")
	}
	oneTimeKeys := mach.account.getOneTimeKeys(mach.Client.UserID, mach.Client.DeviceID)
	if len(oneTimeKeys) == 0 && deviceKeys == nil {
		mach.Log.Trace("No one-time keys nor device keys got when trying to share keys")
		return nil
	}
	req := &mautrix.ReqUploadKeys{
		DeviceKeys:  deviceKeys,
		OneTimeKeys: oneTimeKeys,
	}
	mach.Log.Trace("Uploading %d one-time keys", len(oneTimeKeys))
	_, err := mach.Client.UploadKeys(req)
	if err != nil {
		return err
	}
	mach.account.Shared = true
	mach.SaveAccount()
	mach.Log.Trace("Shared keys and saved account")
	return nil
}
