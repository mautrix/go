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
	UnsupportedAlgorithm                = errors.New("unsupported event encryption algorithm")
	NotEncryptedForMe                   = errors.New("olm event doesn't contain ciphertext for this device")
	UnsupportedOlmMessageType           = errors.New("unsupported olm message type")
	DecryptionFailedWithMatchingSession = errors.New("decryption failed with matching session")
	DecryptionFailedForNormalMessage    = errors.New("decryption failed for normal message")
	SenderMismatch                      = errors.New("mismatched sender in olm payload")
	RecipientMismatch                   = errors.New("mismatched recipient in olm payload")
	RecipientKeyMismatch                = errors.New("mismatched recipient key in olm payload")
)

// DecryptedOlmEvent represents an event that was decrypted from an event encrypted with the m.olm.v1.curve25519-aes-sha2 algorithm.
type DecryptedOlmEvent struct {
	Source *event.Event `json:"-"`

	SenderKey id.SenderKey `json:"-"`

	Sender        id.UserID    `json:"sender"`
	SenderDevice  id.DeviceID  `json:"sender_device"`
	Keys          OlmEventKeys `json:"keys"`
	Recipient     id.UserID    `json:"recipient"`
	RecipientKeys OlmEventKeys `json:"recipient_keys"`

	Type    event.Type    `json:"type"`
	Content event.Content `json:"content"`
}

func (mach *OlmMachine) decryptOlmEvent(evt *event.Event) (*DecryptedOlmEvent, error) {
	content, ok := evt.Content.Parsed.(*event.EncryptedEventContent)
	if !ok {
		return nil, IncorrectEncryptedContentType
	} else if content.Algorithm != id.AlgorithmOlmV1 {
		return nil, UnsupportedAlgorithm
	}
	ownContent, ok := content.OlmCiphertext[mach.account.IdentityKey()]
	if !ok {
		return nil, NotEncryptedForMe
	}
	decrypted, err := mach.decryptAndParseOlmCiphertext(evt.Sender, content.DeviceID, content.SenderKey, ownContent.Type, ownContent.Body)
	if err != nil {
		return nil, err
	}
	decrypted.Source = evt
	return decrypted, nil
}

type OlmEventKeys struct {
	Ed25519 id.Ed25519 `json:"ed25519"`
}

func (mach *OlmMachine) decryptAndParseOlmCiphertext(sender id.UserID, deviceID id.DeviceID, senderKey id.SenderKey, olmType id.OlmMsgType, ciphertext string) (*DecryptedOlmEvent, error) {
	if olmType != id.OlmMsgTypePreKey && olmType != id.OlmMsgTypeMsg {
		return nil, UnsupportedOlmMessageType
	}

	plaintext, err := mach.tryDecryptOlmCiphertext(sender, deviceID, senderKey, olmType, ciphertext)
	if err != nil {
		return nil, err
	}

	var olmEvt DecryptedOlmEvent
	err = json.Unmarshal(plaintext, &olmEvt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse olm payload: %w", err)
	}
	if sender != olmEvt.Sender {
		return nil, SenderMismatch
	} else if mach.Client.UserID != olmEvt.Recipient {
		return nil, RecipientMismatch
	} else if mach.account.SigningKey() != olmEvt.RecipientKeys.Ed25519 {
		return nil, RecipientKeyMismatch
	}

	err = olmEvt.Content.ParseRaw(olmEvt.Type)
	if err != nil && !event.IsUnsupportedContentType(err) {
		return nil, fmt.Errorf("failed to parse content of olm payload event: %w", err)
	}

	olmEvt.SenderKey = senderKey

	return &olmEvt, nil
}

func (mach *OlmMachine) tryDecryptOlmCiphertext(sender id.UserID, deviceID id.DeviceID, senderKey id.SenderKey, olmType id.OlmMsgType, ciphertext string) ([]byte, error) {
	mach.olmLock.Lock()
	defer mach.olmLock.Unlock()

	plaintext, err := mach.tryDecryptOlmCiphertextWithExistingSession(senderKey, olmType, ciphertext)
	if err != nil {
		if err == DecryptionFailedWithMatchingSession {
			mach.Log.Warn("Found matching session yet decryption failed for sender %s with key %s", sender, senderKey)
			mach.markDeviceForUnwedging(sender, senderKey)
		}
		return nil, fmt.Errorf("failed to decrypt olm event: %w", err)
	}

	if plaintext != nil {
		// Decryption successful
		return plaintext, nil
	}

	// Decryption failed with every known session or no known sessions, let's try to create a new session.
	//
	// New sessions can only be created if it's a prekey message, we can't decrypt the message
	// if it isn't one at this point in time anymore, so return early.
	if olmType != id.OlmMsgTypePreKey {
		mach.markDeviceForUnwedging(sender, senderKey)
		return nil, DecryptionFailedForNormalMessage
	}

	mach.Log.Trace("Trying to create inbound session for %s/%s", sender, deviceID)
	session, err := mach.createInboundSession(senderKey, ciphertext)
	if err != nil {
		mach.markDeviceForUnwedging(sender, senderKey)
		return nil, fmt.Errorf("failed to create new session from prekey message: %w", err)
	}
	mach.Log.Debug("Created inbound olm session %s for %s/%s (sender key: %s)", session.ID(), sender, deviceID, senderKey)

	plaintext, err = session.Decrypt(ciphertext, olmType)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt olm event with session created from prekey message: %w", err)
	}

	err = mach.CryptoStore.UpdateSession(senderKey, session)
	if err != nil {
		mach.Log.Warn("Failed to update new olm session in crypto store after decrypting: %v", err)
	}
	return plaintext, nil
}

func (mach *OlmMachine) tryDecryptOlmCiphertextWithExistingSession(senderKey id.SenderKey, olmType id.OlmMsgType, ciphertext string) ([]byte, error) {
	sessions, err := mach.CryptoStore.GetSessions(senderKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get session for %s: %w", senderKey, err)
	}
	for _, session := range sessions {
		if olmType == id.OlmMsgTypePreKey {
			matches, err := session.Internal.MatchesInboundSession(ciphertext)
			if err != nil {
				return nil, fmt.Errorf("failed to check if ciphertext matches inbound session: %w", err)
			} else if !matches {
				continue
			}
		}
		plaintext, err := session.Decrypt(ciphertext, olmType)
		if err != nil {
			if olmType == id.OlmMsgTypePreKey {
				return nil, DecryptionFailedWithMatchingSession
			}
		} else {
			err = mach.CryptoStore.UpdateSession(senderKey, session)
			if err != nil {
				mach.Log.Warn("Failed to update olm session in crypto store after decrypting: %v", err)
			}
			return plaintext, nil
		}
	}
	return nil, nil
}

func (mach *OlmMachine) createInboundSession(senderKey id.SenderKey, ciphertext string) (*OlmSession, error) {
	session, err := mach.account.NewInboundSessionFrom(senderKey, ciphertext)
	if err != nil {
		return nil, err
	}
	mach.saveAccount()
	err = mach.CryptoStore.AddSession(senderKey, session)
	if err != nil {
		mach.Log.Error("Failed to store created inbound session: %v", err)
	}
	return session, nil
}
