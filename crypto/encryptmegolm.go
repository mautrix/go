// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/json"
	"errors"
	"fmt"

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
	RoomID  id.RoomID   `json:"room_id"`
	Type    event.Type  `json:"type"`
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
		return nil, fmt.Errorf("failed to get outbound group session: %w", err)
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
		SessionID:        session.ID(),
		MegolmCiphertext: ciphertext,
		RelatesTo:        getRelatesTo(content),

		// These are deprecated
		SenderKey: mach.account.IdentityKey(),
		DeviceID:  mach.Client.DeviceID,
	}, nil
}

func (mach *OlmMachine) newOutboundGroupSession(roomID id.RoomID) *OutboundGroupSession {
	session := NewOutboundGroupSession(roomID, mach.StateStore.GetEncryptionEvent(roomID))
	signingKey, idKey := mach.account.Keys()
	mach.createGroupSession(idKey, signingKey, roomID, session.ID(), session.Internal.Key(), "create")
	return session
}

type deviceSessionWrapper struct {
	session  *OlmSession
	identity *id.Device
}

// ShareGroupSession shares a group session for a specific room with all the devices of the given user list.
//
// For devices with TrustStateBlacklisted, a m.room_key.withheld event with code=m.blacklisted is sent.
// If AllowUnverifiedDevices is false, a similar event with code=m.unverified is sent to devices with TrustStateUnset
func (mach *OlmMachine) ShareGroupSession(roomID id.RoomID, users []id.UserID) error {
	mach.Log.Debug("Sharing group session for room %s to %v", roomID, users)
	session, err := mach.CryptoStore.GetOutboundGroupSession(roomID)
	if err != nil {
		return fmt.Errorf("failed to get previous outbound group session: %w", err)
	} else if session != nil && session.Shared && !session.Expired() {
		return AlreadyShared
	}
	if session == nil || session.Expired() {
		session = mach.newOutboundGroupSession(roomID)
	}

	withheldCount := 0
	toDeviceWithheld := &mautrix.ReqSendToDevice{Messages: make(map[id.UserID]map[id.DeviceID]*event.Content)}
	olmSessions := make(map[id.UserID]map[id.DeviceID]deviceSessionWrapper)
	missingSessions := make(map[id.UserID]map[id.DeviceID]*id.Device)
	missingUserSessions := make(map[id.DeviceID]*id.Device)
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
			mach.Log.Trace("Trying to find olm sessions to encrypt %s for %s", session.ID(), userID)
			toDeviceWithheld.Messages[userID] = make(map[id.DeviceID]*event.Content)
			olmSessions[userID] = make(map[id.DeviceID]deviceSessionWrapper)
			mach.findOlmSessionsForUser(session, userID, devices, olmSessions[userID], toDeviceWithheld.Messages[userID], missingUserSessions)
			mach.Log.Trace("Found %d sessions, withholding from %d sessions and missing %d sessions to encrypt %s for for %s", len(olmSessions[userID]), len(toDeviceWithheld.Messages[userID]), len(missingUserSessions), session.ID(), userID)
			withheldCount += len(toDeviceWithheld.Messages[userID])
			if len(missingUserSessions) > 0 {
				missingSessions[userID] = missingUserSessions
				missingUserSessions = make(map[id.DeviceID]*id.Device)
			}
			if len(toDeviceWithheld.Messages[userID]) == 0 {
				delete(toDeviceWithheld.Messages, userID)
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

	if len(missingSessions) > 0 {
		mach.Log.Trace("Creating missing outbound sessions")
		err = mach.createOutboundSessions(missingSessions)
		if err != nil {
			mach.Log.Error("Failed to create missing outbound sessions: %v", err)
		}
	}

	for userID, devices := range missingSessions {
		if len(devices) == 0 {
			// No missing sessions
			continue
		}
		output, ok := olmSessions[userID]
		if !ok {
			output = make(map[id.DeviceID]deviceSessionWrapper)
			olmSessions[userID] = output
		}
		withheld, ok := toDeviceWithheld.Messages[userID]
		if !ok {
			withheld = make(map[id.DeviceID]*event.Content)
			toDeviceWithheld.Messages[userID] = withheld
		}
		mach.Log.Trace("Trying to find olm sessions to encrypt %s for %s (post-fetch retry)", session.ID(), userID)
		mach.findOlmSessionsForUser(session, userID, devices, output, withheld, nil)
		mach.Log.Trace("Found %d sessions and withholding from %d sessions to encrypt %s for for %s (post-fetch retry)", len(output), len(withheld), session.ID(), userID)
		withheldCount += len(toDeviceWithheld.Messages[userID])
		if len(toDeviceWithheld.Messages[userID]) == 0 {
			delete(toDeviceWithheld.Messages, userID)
		}
	}

	err = mach.encryptAndSendGroupSession(session, olmSessions)
	if err != nil {
		return fmt.Errorf("failed to share group session: %w", err)
	}

	if len(toDeviceWithheld.Messages) > 0 {
		mach.Log.Trace("Sending to-device messages to %d devices of %d users to report withheld keys in %s", withheldCount, len(toDeviceWithheld.Messages), roomID)
		// TODO remove the next 4 lines once clients support m.room_key.withheld
		_, err = mach.Client.SendToDevice(event.ToDeviceOrgMatrixRoomKeyWithheld, toDeviceWithheld)
		if err != nil {
			mach.Log.Warn("Failed to report withheld keys in %s (legacy event type): %v", roomID, err)
		}
		_, err = mach.Client.SendToDevice(event.ToDeviceRoomKeyWithheld, toDeviceWithheld)
		if err != nil {
			mach.Log.Warn("Failed to report withheld keys in %s: %v", roomID, err)
		}
	}

	mach.Log.Debug("Group session %s for %s successfully shared", session.ID(), roomID)
	session.Shared = true
	return mach.CryptoStore.AddOutboundGroupSession(session)
}

func (mach *OlmMachine) encryptAndSendGroupSession(session *OutboundGroupSession, olmSessions map[id.UserID]map[id.DeviceID]deviceSessionWrapper) error {
	mach.olmLock.Lock()
	defer mach.olmLock.Unlock()
	mach.Log.Trace("Encrypting group session %s for all found devices", session.ID())
	deviceCount := 0
	toDevice := &mautrix.ReqSendToDevice{Messages: make(map[id.UserID]map[id.DeviceID]*event.Content)}
	for userID, sessions := range olmSessions {
		if len(sessions) == 0 {
			continue
		}
		output := make(map[id.DeviceID]*event.Content)
		toDevice.Messages[userID] = output
		for deviceID, device := range sessions {
			mach.Log.Trace("Encrypting group session %s for %s of %s", session.ID(), deviceID, userID)
			content := mach.encryptOlmEvent(device.session, device.identity, event.ToDeviceRoomKey, session.ShareContent())
			output[deviceID] = &event.Content{Parsed: content}
			deviceCount++
			mach.Log.Trace("Encrypted group session %s for %s of %s", session.ID(), deviceID, userID)
		}
	}

	mach.Log.Trace("Sending to-device to %d devices of %d users to share group session %s", deviceCount, len(toDevice.Messages), session.ID())
	_, err := mach.Client.SendToDevice(event.ToDeviceEncrypted, toDevice)
	return err
}

func (mach *OlmMachine) findOlmSessionsForUser(session *OutboundGroupSession, userID id.UserID, devices map[id.DeviceID]*id.Device, output map[id.DeviceID]deviceSessionWrapper, withheld map[id.DeviceID]*event.Content, missingOutput map[id.DeviceID]*id.Device) {
	for deviceID, device := range devices {
		userKey := UserDevice{UserID: userID, DeviceID: deviceID}
		if state := session.Users[userKey]; state != OGSNotShared {
			continue
		} else if userID == mach.Client.UserID && deviceID == mach.Client.DeviceID {
			session.Users[userKey] = OGSIgnored
		} else if device.Trust == id.TrustStateBlacklisted {
			mach.Log.Debug(
				"Not encrypting group session %s for %s of %s: device is blacklisted",
				session.ID(), deviceID, userID,
			)
			withheld[deviceID] = &event.Content{Parsed: &event.RoomKeyWithheldEventContent{
				RoomID:    session.RoomID,
				Algorithm: id.AlgorithmMegolmV1,
				SessionID: session.ID(),
				SenderKey: mach.account.IdentityKey(),
				Code:      event.RoomKeyWithheldBlacklisted,
				Reason:    "Device is blacklisted",
			}}
			session.Users[userKey] = OGSIgnored
		} else if trustState := mach.ResolveTrust(device); trustState < mach.SendKeysMinTrust {
			mach.Log.Debug(
				"Not encrypting group session %s for %s of %s: device is not verified (minimum: %s, device: %s)",
				session.ID(), deviceID, userID, mach.SendKeysMinTrust, trustState,
			)
			withheld[deviceID] = &event.Content{Parsed: &event.RoomKeyWithheldEventContent{
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
			output[deviceID] = deviceSessionWrapper{
				session:  deviceSession,
				identity: device,
			}
			session.Users[userKey] = OGSAlreadyShared
		}
	}
}
