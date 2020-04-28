// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/json"

	"github.com/pkg/errors"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	AlreadyShared  = errors.New("group session already shared")
	NoGroupSession = errors.New("no group session created")
)

func (mach *OlmMachine) EncryptMegolmEvent(roomID id.RoomID, evtType event.Type, content event.Content) (*event.EncryptedEventContent, error) {
	session, err := mach.Store.GetOutboundGroupSession(roomID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get outbound group session")
	} else if session == nil {
		return nil, NoGroupSession
	}
	plaintext, err := json.Marshal(&MegolmEvent{
		RoomID:  roomID,
		Type:    evtType,
		Content: content,
	})
	if err != nil {
		return nil, err
	}
	ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	_, idKey := mach.account.IdentityKeys()
	return &event.EncryptedEventContent{
		Algorithm:        id.AlgorithmMegolmV1,
		SenderKey:        idKey,
		DeviceID:         mach.Client.DeviceID,
		SessionID:        session.ID(),
		MegolmCiphertext: ciphertext,
	}, nil
}

func (mach *OlmMachine) newOutboundGroupSession(roomID id.RoomID) *OutboundGroupSession {
	session := NewOutboundGroupSession(roomID)
	signingKey, idKey := mach.account.IdentityKeys()
	mach.createGroupSession(idKey, signingKey, roomID, session.ID(), session.Key())
	return session
}

func (mach *OlmMachine) ShareGroupSession(roomID id.RoomID, users []id.UserID) error {
	mach.Log.Trace("Sharing group session for room %s", roomID)
	session, err := mach.Store.GetOutboundGroupSession(roomID)
	if err != nil {
		return errors.Wrap(err, "failed to get previous outbound group session")
	} else if session != nil && session.Shared {
		return AlreadyShared
	}
	if session == nil || session.Expired() {
		session = mach.newOutboundGroupSession(roomID)
	}

	toDevice := &mautrix.ReqSendToDevice{Messages: make(map[id.UserID]map[id.DeviceID]*event.Content)}
	missingSessions := make(map[id.UserID]map[id.DeviceID]*DeviceIdentity)
	var fetchKeys []id.UserID

	for _, userID := range users {
		devices, err := mach.Store.GetDevices(userID)
		if err != nil {
			mach.Log.Error("Failed to get devices of %s", userID)
		} else if devices == nil {
			mach.Log.Trace("GetDevices returned nil for %s, will fetch keys and retry", userID)
			fetchKeys = append(fetchKeys, userID)
		} else if len(devices) == 0 {
			mach.Log.Trace("%s has no devices, skipping", userID)
		} else {
			mach.Log.Trace("Trying to encrypt group session %s for %s", session.ID(), userID)
			toDevice.Messages[userID], missingSessions[userID] = mach.encryptGroupSessionForUser(session, userID, devices)
		}
	}

	mach.Log.Trace("Fetching missing keys for %d users (%v)", len(fetchKeys), fetchKeys)
	for userID, devices := range mach.fetchKeys(fetchKeys, "") {
		mach.Log.Trace("Got %d device keys for %s", len(devices), userID)
		missingSessions[userID] = devices
	}

	mach.Log.Trace("Creating missing outbound sessions")
	err = mach.createOutboundSessions(missingSessions)
	if err != nil {
		mach.Log.Error("Failed to create missing outbound sessions: %v", err)
	}

	for userID, devices := range missingSessions {
		mach.Log.Trace("Trying to encrypt group session %s for %s (post-fetch retry)", session.ID(), userID)
		toDevice.Messages[userID], _ = mach.encryptGroupSessionForUser(session, userID, devices)
	}

	mach.Log.Trace("Sending %d to-device messages to share group session for %s", len(toDevice.Messages), roomID)
	_, err = mach.Client.SendToDevice(event.ToDeviceEncrypted, toDevice)
	if err != nil {
		return errors.Wrap(err, "failed to share group session")
	}
	mach.Log.Debug("Group session for %s successfully shared", roomID)
	session.Shared = true
	return mach.Store.PutOutboundGroupSession(roomID, session)
}

func (mach *OlmMachine) encryptGroupSessionForUser(session *OutboundGroupSession, userID id.UserID, devices map[id.DeviceID]*DeviceIdentity) (map[id.DeviceID]*event.Content, map[id.DeviceID]*DeviceIdentity) {
	toDeviceMessages := make(map[id.DeviceID]*event.Content)
	missingSessions := make(map[id.DeviceID]*DeviceIdentity)

	for deviceID, device := range devices {
		userKey := UserDevice{UserID: userID, DeviceID: deviceID}
		if userID == mach.Client.UserID && deviceID == mach.Client.DeviceID {
			session.Users[userKey] = OGSIgnored
		}

		// TODO blacklisting and verification checking should be done around here

		if state := session.Users[userKey]; state != OGSNotShared {
			continue
		}

		deviceSession, err := mach.Store.GetLatestSession(device.IdentityKey)
		if err != nil {
			mach.Log.Error("Failed to get session for %s of %s: %v", deviceID, userID, err)
		} else if deviceSession == nil {
			mach.Log.Warn("Didn't find a session for %s of %s", deviceID, userID)
			missingSessions[deviceID] = device
		} else {
			content := mach.encryptOlmEvent(deviceSession, device, event.ToDeviceRoomKey, session.ShareContent())
			toDeviceMessages[deviceID] = &event.Content{Parsed: content}
			session.Users[userKey] = OGSAlreadyShared
			mach.Log.Trace("Encrypted group session %s for %s of %s", session.ID(), deviceID, userID)
		}
	}

	return toDeviceMessages, missingSessions
}
