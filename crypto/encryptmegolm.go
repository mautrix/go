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

func getRelatesTo(content interface{}) *event.RelatesTo {
	contentStruct, ok := content.(*event.Content)
	if ok {
		content = contentStruct.Parsed
	}
	relatable, ok := content.(event.Relatable)
	if ok {
		return relatable.OptionalGetRelatesTo()
	}
	return nil
}

type rawMegolmEvent struct {
	RoomID  id.RoomID     `json:"room_id"`
	Type    event.Type    `json:"type"`
	Content interface{} `json:"content"`
}

// IsShareError returns true if the error is caused by the lack of an outgoing megolm session and can be solved with OlmMachine.ShareGroupSession
func IsShareError(err error) bool {
	return err == SessionExpired || err == SessionNotShared || err == NoGroupSession
}

// EncryptMegolmEvent encrypts data with the m.megolm.v1.aes-sha2 algorithm.
//
// If you use the event.Content struct, make sure you pass a pointer to the struct,
// as JSON serialization will not work correctly otherwise.
func (mach *OlmMachine) EncryptMegolmEvent(roomID id.RoomID, evtType event.Type, content interface{}) (*event.EncryptedEventContent, error) {
	mach.Log.Trace("Encrypting event of type %s for %s", evtType.Type, roomID)
	session, err := mach.CryptoStore.GetOutboundGroupSession(roomID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get outbound group session")
	} else if session == nil {
		return nil, NoGroupSession
	}
	plaintext, err := json.Marshal(&rawMegolmEvent{
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
	err = mach.CryptoStore.UpdateOutboundGroupSession(session)
	if err != nil {
		mach.Log.Warn("Failed to update megolm session in crypto store after encrypting: %v", err)
	}
	return &event.EncryptedEventContent{
		Algorithm:        id.AlgorithmMegolmV1,
		SenderKey:        mach.account.IdentityKey(),
		DeviceID:         mach.Client.DeviceID,
		SessionID:        session.ID(),
		MegolmCiphertext: ciphertext,
		RelatesTo:        getRelatesTo(content),
	}, nil
}

func (mach *OlmMachine) newOutboundGroupSession(roomID id.RoomID) *OutboundGroupSession {
	session := NewOutboundGroupSession(roomID, mach.StateStore.GetEncryptionEvent(roomID))
	signingKey, idKey := mach.account.Keys()
	mach.createGroupSession(idKey, signingKey, roomID, session.ID(), session.Internal.Key())
	return session
}

// ShareGroupSession shares a group session for a specific room with all the devices of the given user list.
//
// For devices with TrustStateBlacklisted, a m.room_key.withheld event with code=m.blacklisted is sent.
// If AllowUnverifiedDevices is false, a similar event with code=m.unverified is sent to devices with TrustStateUnset
func (mach *OlmMachine) ShareGroupSession(roomID id.RoomID, users []id.UserID) error {
	mach.Log.Trace("Sharing group session for room %s to %v", roomID, users)
	session, err := mach.CryptoStore.GetOutboundGroupSession(roomID)
	if err != nil {
		return errors.Wrap(err, "failed to get previous outbound group session")
	} else if session != nil && session.Shared && !session.Expired() {
		return AlreadyShared
	}
	if session == nil || session.Expired() {
		session = mach.newOutboundGroupSession(roomID)
	}

	toDevice := &mautrix.ReqSendToDevice{Messages: make(map[id.UserID]map[id.DeviceID]*event.Content)}
	missingSessions := make(map[id.UserID]map[id.DeviceID]*DeviceIdentity)
	missingUserSessions := make(map[id.DeviceID]*DeviceIdentity)
	var fetchKeys []id.UserID

	for _, userID := range users {
		devices, err := mach.CryptoStore.GetDevices(userID)
		if err != nil {
			mach.Log.Error("Failed to get devices of %s", userID)
		} else if devices == nil {
			mach.Log.Trace("GetDevices returned nil for %s, will fetch keys and retry", userID)
			fetchKeys = append(fetchKeys, userID)
		} else if len(devices) == 0 {
			mach.Log.Trace("%s has no devices, skipping", userID)
		} else {
			mach.Log.Trace("Trying to encrypt group session %s for %s", session.ID(), userID)
			toDevice.Messages[userID] = make(map[id.DeviceID]*event.Content)
			mach.encryptGroupSessionForUser(session, userID, devices, toDevice.Messages[userID], missingUserSessions)
			if len(missingUserSessions) > 0 {
				missingSessions[userID] = missingUserSessions
				missingUserSessions = make(map[id.DeviceID]*DeviceIdentity)
			}
		}
	}

	if len(fetchKeys) > 0 {
		mach.Log.Trace("Fetching missing keys for %v", fetchKeys)
		for userID, devices := range mach.fetchKeys(fetchKeys, "", true) {
			mach.Log.Trace("Got %d device keys for %s", len(devices), userID)
			missingSessions[userID] = devices
		}
	}

	mach.Log.Trace("Creating missing outbound sessions")
	err = mach.createOutboundSessions(missingSessions)
	if err != nil {
		mach.Log.Error("Failed to create missing outbound sessions: %v", err)
	}

	for userID, devices := range missingSessions {
		if len(devices) == 0 {
			// No missing sessions
			continue
		}
		output, ok := toDevice.Messages[userID]
		if !ok {
			output = make(map[id.DeviceID]*event.Content)
			toDevice.Messages[userID] = output
		}
		mach.Log.Trace("Trying to encrypt group session %s for %s (post-fetch retry)", session.ID(), userID)
		mach.encryptGroupSessionForUser(session, userID, devices, output, nil)
	}

	mach.Log.Trace("Sending %d to-device messages to share group session for %s", len(toDevice.Messages), roomID)
	// FIXME room key withheld events need to be sent differently
	_, err = mach.Client.SendToDevice(event.ToDeviceEncrypted, toDevice)
	if err != nil {
		return errors.Wrap(err, "failed to share group session")
	}
	mach.Log.Debug("Group session for %s successfully shared", roomID)
	session.Shared = true
	return mach.CryptoStore.AddOutboundGroupSession(session)
}

func (mach *OlmMachine) encryptGroupSessionForUser(session *OutboundGroupSession, userID id.UserID, devices map[id.DeviceID]*DeviceIdentity, output map[id.DeviceID]*event.Content, missingOutput map[id.DeviceID]*DeviceIdentity) {
	for deviceID, device := range devices {
		userKey := UserDevice{UserID: userID, DeviceID: deviceID}
		if state := session.Users[userKey]; state != OGSNotShared {
			continue
		} else if userID == mach.Client.UserID && deviceID == mach.Client.DeviceID {
			session.Users[userKey] = OGSIgnored
		} else if device.Trust == TrustStateBlacklisted {
			mach.Log.Debug("Not encrypting group session %s for %s of %s: device is blacklisted", session.ID(), deviceID, userID)
			output[deviceID] = &event.Content{Parsed: event.RoomKeyWithheldEventContent{
				RoomID:    session.RoomID,
				Algorithm: id.AlgorithmMegolmV1,
				SessionID: session.ID(),
				SenderKey: mach.account.IdentityKey(),
				Code:      event.RoomKeyWithheldBlacklisted,
				Reason:    "Device is blacklisted",
			}}
			session.Users[userKey] = OGSIgnored
		} else if !mach.AllowUnverifiedDevices && device.Trust == TrustStateUnset {
			mach.Log.Debug("Not encrypting group session %s for %s of %s: device is not verified", session.ID(), deviceID, userID)
			output[deviceID] = &event.Content{Parsed: event.RoomKeyWithheldEventContent{
				RoomID:    session.RoomID,
				Algorithm: id.AlgorithmMegolmV1,
				SessionID: session.ID(),
				SenderKey: mach.account.IdentityKey(),
				Code:      event.RoomKeyWithheldUnverified,
				Reason:    "This device does not encrypt messages for unverified devices",
			}}
			session.Users[userKey] = OGSIgnored
		} else if deviceSession, err := mach.CryptoStore.GetLatestSession(device.IdentityKey); err != nil {
			mach.Log.Error("Failed to get session for %s of %s: %v", deviceID, userID, err)
		} else if deviceSession == nil {
			mach.Log.Warn("Didn't find a session for %s of %s", deviceID, userID)
			if missingOutput != nil {
				missingOutput[deviceID] = device
			}
		} else {
			content := mach.encryptOlmEvent(deviceSession, device, event.ToDeviceRoomKey, session.ShareContent())
			output[deviceID] = &event.Content{Parsed: content}
			session.Users[userKey] = OGSAlreadyShared
			mach.Log.Trace("Encrypted group session %s for %s of %s", session.ID(), deviceID, userID)
		}
	}
}
