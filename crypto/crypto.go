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
	Debugfln(message string, args ...interface{})
}

type OlmMachine struct {
	client *mautrix.Client
	store  Store

	account       *OlmAccount
	sessions      map[id.SenderKey][]*OlmSession
	groupSessions map[id.RoomID]map[id.SenderKey]map[id.SessionID]*InboundGroupSession
	log           Logger
}

func NewOlmMachine(client *mautrix.Client, store Store) *OlmMachine {
	return &OlmMachine{
		client: client,
		store:  store,
	}
}

func (mach *OlmMachine) Load() (err error) {
	mach.account, err = mach.store.LoadAccount()
	if err != nil {
		return
	}
	if mach.account == nil {
		mach.account = &OlmAccount{
			Account: olm.NewAccount(),
		}
	}
	return nil
}

func (mach *OlmMachine) SaveAccount() {
	err := mach.store.SaveAccount(mach.account)
	if err != nil {
		mach.log.Debugfln("Failed to save account: %v", err)
	}
}

func (mach *OlmMachine) GetSessions(senderKey id.SenderKey) []*OlmSession {
	sessions, ok := mach.sessions[senderKey]
	if !ok {
		sessions, err := mach.store.LoadSessions(senderKey)
		if err != nil {
			mach.log.Debugfln("Failed to load sessions for %s: %v", senderKey, err)
			sessions = make([]*OlmSession, 0)
		}
		mach.sessions[senderKey] = sessions
	}
	return sessions
}

func (mach *OlmMachine) SaveSession(senderKey id.SenderKey, session *OlmSession) {
	mach.sessions[senderKey] = append(mach.sessions[senderKey], session)
	err := mach.store.SaveSessions(senderKey, mach.sessions[senderKey])
	if err != nil {
		mach.log.Debugfln("Failed to save sessions for %s: %v", senderKey, err)
	}
}

func (mach *OlmMachine) ProcessSyncResponse(resp *mautrix.RespSync) {
	for _, evt := range resp.ToDevice.Events {
		evt.Type.Class = event.ToDeviceEventType
		err := evt.Content.ParseRaw(evt.Type)
		if err != nil {
			continue
		}
		mach.HandleToDeviceEvent(evt)
	}

	min := mach.account.MaxNumberOfOneTimeKeys() / 2
	if resp.DeviceOneTimeKeysCount.SignedCurve25519 <= int(min) {
		err := mach.ShareKeys()
		if err != nil {
			mach.log.Debugfln("Failed to share keys: %v", err)
		}
	}
}

func (mach *OlmMachine) HandleToDeviceEvent(evt *event.Event) {
	switch evt.Content.Parsed.(type) {
	case *event.EncryptedEventContent:
		decryptedEvt, err := mach.DecryptOlmEvent(evt)
		if err != nil {
			mach.log.Debugfln("Failed to decrypt to-device event:", err)
			return
		}
		switch content := decryptedEvt.Content.Parsed.(type) {
		case *event.RoomKeyEventContent:
			mach.receiveRoomKey(decryptedEvt, content)
		}
		// TODO unencrypted to-device events should be handled here. At least m.room_key_request and m.verification.start
	}
}

func (mach *OlmMachine) getGroupSessions(roomID id.RoomID, senderKey id.SenderKey) map[id.SessionID]*InboundGroupSession {
	roomGroupSessions, ok := mach.groupSessions[roomID]
	if !ok {
		roomGroupSessions = make(map[id.SenderKey]map[id.SessionID]*InboundGroupSession)
		mach.groupSessions[roomID] = roomGroupSessions
	}
	senderGroupSessions, ok := roomGroupSessions[senderKey]
	if !ok {
		senderGroupSessions = make(map[id.SessionID]*InboundGroupSession)
		roomGroupSessions[senderKey] = senderGroupSessions
	}
	return senderGroupSessions
}

func (mach *OlmMachine) createGroupSession(senderKey id.SenderKey, signingKey id.Ed25519, roomID id.RoomID, sessionID id.SessionID, sessionKey string) {
	igs, err := NewInboundGroupSession(senderKey, signingKey, roomID, sessionKey)
	if err != nil {
		mach.log.Debugfln("Failed to create inbound group session: %v", err)
	} else if igs.ID() != sessionID {
		mach.log.Debugfln("Mismatched session ID while creating inbound group session")
	} else {
		mach.getGroupSessions(roomID, senderKey)[sessionID] = igs
		// TODO save mach.groupSessions
	}
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
	}
	oneTimeKeys := mach.account.getOneTimeKeys(mach.client.UserID, mach.client.DeviceID)
	if len(oneTimeKeys) == 0 && deviceKeys == nil {
		return nil
	}
	req := &mautrix.ReqUploadKeys{
		DeviceKeys:  deviceKeys,
		OneTimeKeys: oneTimeKeys,
	}
	_, err := mach.client.UploadKeys(req)
	if err != nil {
		return err
	}
	mach.account.Shared = true
	mach.SaveAccount()
	return nil
}
