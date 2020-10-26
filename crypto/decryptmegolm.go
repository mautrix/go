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

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	IncorrectEncryptedContentType = errors.New("event content is not instance of *event.EncryptedEventContent")
	NoSessionFound                = errors.New("failed to decrypt megolm event: no session with given ID found")
	DuplicateMessageIndex         = errors.New("duplicate megolm message index")
	WrongRoom                     = errors.New("encrypted megolm event is not intended for this room")
	DeviceKeyMismatch             = errors.New("device keys in event and verified device info do not match")
)

type megolmEvent struct {
	RoomID  id.RoomID     `json:"room_id"`
	Type    event.Type    `json:"type"`
	Content event.Content `json:"content"`
}

// DecryptMegolmEvent decrypts an m.room.encrypted event where the algorithm is m.megolm.v1.aes-sha2
func (mach *OlmMachine) DecryptMegolmEvent(evt *event.Event) (*event.Event, error) {
	content, ok := evt.Content.Parsed.(*event.EncryptedEventContent)
	if !ok {
		return nil, IncorrectEncryptedContentType
	} else if content.Algorithm != id.AlgorithmMegolmV1 {
		return nil, UnsupportedAlgorithm
	}
	sess, err := mach.CryptoStore.GetGroupSession(evt.RoomID, content.SenderKey, content.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group session: %w", err)
	} else if sess == nil {
		mach.checkIfWedged(evt)
		return nil, fmt.Errorf("%w (ID %s)", NoSessionFound, content.SessionID)
	}
	plaintext, messageIndex, err := sess.Internal.Decrypt(content.MegolmCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt megolm event: %w", err)
	} else if !mach.CryptoStore.ValidateMessageIndex(content.SenderKey, content.SessionID, evt.ID, messageIndex, evt.Timestamp) {
		return nil, DuplicateMessageIndex
	}

	var verified bool
	ownSigningKey, ownIdentityKey := mach.account.Keys()
	if content.DeviceID == mach.Client.DeviceID && sess.SigningKey == ownSigningKey && content.SenderKey == ownIdentityKey {
		verified = true
	} else {
		device, err := mach.GetOrFetchDevice(evt.Sender, content.DeviceID)
		if err != nil {
			// We don't want to throw these errors as the message can still be decrypted.
			mach.Log.Debug("Failed to get device %s/%s to verify session %s: %v", evt.Sender, content.DeviceID, sess.ID(), err)
			// TODO maybe store the info that the device is deleted?
		} else if mach.IsDeviceTrusted(device) && len(sess.ForwardingChains) == 0 { // For some reason, matrix-nio had a comment saying not to events decrypted using a forwarded key as verified.
			if device.SigningKey != sess.SigningKey || device.IdentityKey != content.SenderKey {
				return nil, DeviceKeyMismatch
			}
			verified = true
		}
	}

	megolmEvt := &megolmEvent{}
	err = json.Unmarshal(plaintext, &megolmEvt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse megolm payload: %w", err)
	} else if megolmEvt.RoomID != evt.RoomID {
		return nil, WrongRoom
	}
	megolmEvt.Type.Class = evt.Type.Class
	err = megolmEvt.Content.ParseRaw(megolmEvt.Type)
	if err != nil {
		if event.IsUnsupportedContentType(err) {
			mach.Log.Warn("Unsupported event type %s in encrypted event %s", megolmEvt.Type.Repr(), evt.ID)
		} else {
			return nil, fmt.Errorf("failed to parse content of megolm payload event: %w", err)
		}
	}
	if content.RelatesTo != nil {
		relatable, ok := megolmEvt.Content.Parsed.(event.Relatable)
		if ok {
			if relatable.OptionalGetRelatesTo() == nil {
				relatable.SetRelatesTo(content.RelatesTo)
			} else {
				mach.Log.Trace("Not overriding relation data in %s, as encrypted payload already has it", evt.ID)
			}
		} else {
			mach.Log.Warn("Encrypted event %s has relation data, but content type %T (%s) doesn't support it", evt.ID, megolmEvt.Content.Parsed, megolmEvt.Type.String())
		}
	}
	megolmEvt.Type.Class = evt.Type.Class
	return &event.Event{
		Sender:    evt.Sender,
		Type:      megolmEvt.Type,
		Timestamp: evt.Timestamp,
		ID:        evt.ID,
		RoomID:    evt.RoomID,
		Content:   megolmEvt.Content,
		Unsigned:  evt.Unsigned,
		Mautrix: event.MautrixInfo{
			Verified: verified,
		},
	}, nil
}
