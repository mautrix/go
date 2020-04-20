// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/olm"
)

var (
	IncorrectEncryptedContentType       = errors.New("event content is not instance of *event.EncryptedEventContent")
	UnsupportedAlgorithm                = errors.New("unsupported event encryption algorithm")
	NotEncryptedForMe                   = errors.New("olm event doesn't contain ciphertext for this device")
	UnsupportedOlmMessageType           = errors.New("unsupported olm message type")
	DecryptionFailedWithMatchingSession = errors.New("decryption failed with matching session")
	DecryptionFailedForNormalMessage    = errors.New("decryption failed for normal message")

	SenderMismatch       = errors.New("mismatched sender in olm payload")
	RecipientMismatch    = errors.New("mismatched recipient in olm payload")
	RecipientKeyMismatch = errors.New("mismatched recipient key in olm payload")
)

func (mach *OlmMachine) DecryptMegolmEvent(evt *event.Event) (*event.Event, error) {
	content, ok := evt.Content.Parsed.(*event.EncryptedEventContent)
	if !ok {
		return nil, IncorrectEncryptedContentType
	}
	fmt.Println(content.Algorithm)
	// TODO
	return nil, nil
}

type OlmEventKeys struct {
	Ed25519 string `json:"ed25519"`
}

type OlmEvent struct {
	Source *event.Event `json:"-"`

	SenderKey     string       `json:"-"`

	Sender        id.UserID    `json:"sender"`
	SenderDevice  id.DeviceID  `json:"sender_device"`
	Keys          OlmEventKeys `json:"keys"`
	Recipient     id.UserID    `json:"recipient"`
	RecipientKeys OlmEventKeys `json:"recipient_keys"`

	Type    event.Type    `json:"type"`
	Content event.Content `json:"content"`
}

func (mach *OlmMachine) createInboundSession(senderKey, ciphertext string) (*OlmSession, error) {
	session, err := mach.account.NewInboundSessionFrom(senderKey, ciphertext)
	if err != nil {
		return nil, err
	}
	mach.SaveAccount()
	mach.SaveSession(senderKey, session)
	return session, nil
}

func (mach *OlmMachine) markDeviceForUnwedging(sender id.UserID, senderKey string) {
	// TODO implement
}

func (mach *OlmMachine) DecryptOlmEvent(evt *event.Event) (*OlmEvent, error) {
	content, ok := evt.Content.Parsed.(*event.EncryptedEventContent)
	if !ok {
		return nil, IncorrectEncryptedContentType
	} else if content.Algorithm != event.AlgorithmOlmV1 {
		return nil, UnsupportedAlgorithm
	}
	_, ownKey := mach.account.IdentityKeys()
	ownContent, ok := content.OlmCiphertext[string(ownKey)]
	if !ok {
		return nil, NotEncryptedForMe
	}
	return mach.decryptOlmEvent(evt, content.SenderKey, ownContent.Type, ownContent.Body)
}

func (mach *OlmMachine) decryptOlmEvent(evt *event.Event, senderKey string, olmType event.OlmMessageType, ciphertext string) (*OlmEvent, error) {
	if olmType != event.OlmPreKeyMessage && olmType != event.OlmNormalMessage {
		return nil, UnsupportedOlmMessageType
	}

	plaintext, err := mach.tryDecryptOlmEvent(senderKey, olmType, ciphertext)
	if err != nil {
		if err == DecryptionFailedWithMatchingSession {
			mach.log.Debugfln("Found matching session yet decryption failed for sender %s with key %s", evt.Sender, senderKey)
			mach.markDeviceForUnwedging(evt.Sender, senderKey)
		}
		return nil, err
	}

	// Decryption failed with every known session or no known sessions, let's try to create a new session.
	if plaintext == nil {
		// New sessions can only be created if it's a prekey message, we can't decrypt the message
		// if it isn't one at this point in time anymore, so return early.
		if olmType != event.OlmNormalMessage {
			mach.markDeviceForUnwedging(evt.Sender, senderKey)
			return nil, DecryptionFailedForNormalMessage
		}

		session, err := mach.createInboundSession(senderKey, ciphertext)
		if err != nil {
			mach.markDeviceForUnwedging(evt.Sender, senderKey)
			return nil, errors.Wrap(err, "failed to create new session from prekey message")
		}

		plaintext, err = session.Decrypt(ciphertext, olm.MsgType(olmType))
		if err != nil {
			return nil, errors.Wrap(err, "failed to decrypt message with session created from prekey message")
		}
	}

	var olmEvt OlmEvent
	err = json.Unmarshal(plaintext, &olmEvt)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse olm payload")
	}
	if evt.Sender != olmEvt.Sender {
		return nil, SenderMismatch
	} else if mach.client.UserID != olmEvt.Recipient {
		return nil, RecipientMismatch
	} else if ed25519, _ := mach.account.IdentityKeys(); string(ed25519) != olmEvt.RecipientKeys.Ed25519 {
		return nil, RecipientKeyMismatch
	}

	err = olmEvt.Content.ParseRaw(olmEvt.Type)
	if err != nil && !event.IsUnsupportedContentType(err) {
		return nil, errors.Wrap(err, "failed to parse content of olm payload event")
	}

	olmEvt.Source = evt
	olmEvt.SenderKey = senderKey

	return &olmEvt, nil
}

func (mach *OlmMachine) tryDecryptOlmEvent(senderKey string, olmType event.OlmMessageType, ciphertext string) ([]byte, error) {
	for _, session := range mach.GetSessions(senderKey) {
		if olmType == event.OlmPreKeyMessage {
			matches, err := session.MatchesInboundSession(ciphertext)
			if err != nil {
				return nil, err
			} else if !matches {
				continue
			}
		}
		plaintext, err := session.Decrypt(ciphertext, olm.MsgType(olmType))
		if err != nil {
			if olmType == event.OlmPreKeyMessage {
				return nil, DecryptionFailedWithMatchingSession
			}
		} else {
			return plaintext, nil
		}
	}
	return nil, nil
}
