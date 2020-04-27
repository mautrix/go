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
	session, err := mach.store.GetOutboundGroupSession(roomID)
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
		DeviceID:         mach.client.DeviceID,
		SessionID:        session.ID(),
		MegolmCiphertext: ciphertext,
	}, nil
}

func (mach *OlmMachine) newOutboundGroupSession(roomID id.RoomID) *OutboundGroupSession {
	session := NewOutboundGroupSession()
	signingKey, idKey := mach.account.IdentityKeys()
	mach.createGroupSession(idKey, signingKey, roomID, session.ID(), session.Key())
	return session
}

func (mach *OlmMachine) ShareGroupSession(roomID id.RoomID, users []id.UserID) error {
	mach.log.Trace("Sharing group session for room %s", roomID)
	session, err := mach.store.GetOutboundGroupSession(roomID)
	if err != nil {
		return errors.Wrap(err, "failed to get previous outbound group session")
	}
	if session == nil || session.Expired() {
		session = mach.newOutboundGroupSession(roomID)
	} else if session.Shared {
		return AlreadyShared
	}

	keyContent := event.Content{Parsed: &event.RoomKeyEventContent{
		Algorithm:  id.AlgorithmMegolmV1,
		RoomID:     roomID,
		SessionID:  session.ID(),
		SessionKey: session.Key(),
	}}

	toDevice := &mautrix.ReqSendToDevice{Messages: make(map[id.UserID]map[id.DeviceID]*event.Content)}

	for _, userID := range users {
		devices, err := mach.store.GetDevices(userID)
		if err != nil {
			mach.log.Warn("Failed to get devices of %s", userID)
			continue
		}
		if len(devices) == 0 {
			mach.FetchKeys([]id.UserID{userID}, "")
			devices, err = mach.store.GetDevices(userID)
			if err != nil {
				mach.log.Warn("Failed to get devices of %s", userID)
				continue
			}
		}

		toDeviceMessages := make(map[id.DeviceID]*event.Content)
		toDevice.Messages[userID] = toDeviceMessages

		for deviceID, device := range devices {
			userKey := UserDevice{UserID: userID, DeviceID: deviceID}
			if userID == mach.client.UserID && deviceID == mach.client.DeviceID {
				session.Users[userKey] = OGSIgnored
			}

			// TODO blacklisting and verification checking should be done around here

			if state := session.Users[userKey]; state != OGSNotShared {
				continue
			}

			deviceSession, err := mach.store.GetLatestSession(device.IdentityKey)
			if err != nil {
				mach.log.Warn("Failed to get session for %s of %s: %v", deviceID, userID, err)
				continue
			} else if deviceSession == nil {
				// TODO we should probably be creating these sessions somewhere
				deviceSession, err = mach.createOutboundSession(userID, deviceID, device.IdentityKey, device.SigningKey)
				if err != nil {
					mach.log.Warn("Failed to create session for %s of %s: %v", deviceID, userID, err)
					continue
				}
			}

			content := mach.encryptOlmEvent(deviceSession, device, event.ToDeviceRoomKey, keyContent)
			toDeviceMessages[deviceID] = &event.Content{Parsed: content}
			session.Users[userKey] = OGSAlreadyShared
		}
	}

	_, err = mach.client.SendToDevice(event.ToDeviceEncrypted, toDevice)
	if err != nil {
		return errors.Wrap(err, "failed to share group session")
	}
	session.Shared = true
	return mach.store.PutOutboundGroupSession(roomID, session)
}
