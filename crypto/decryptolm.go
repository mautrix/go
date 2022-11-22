// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

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

func (mach *OlmMachine) decryptOlmEvent(evt *event.Event, traceID string) (*DecryptedOlmEvent, error) {
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
	decrypted, err := mach.decryptAndParseOlmCiphertext(evt.Sender, content.SenderKey, ownContent.Type, ownContent.Body, traceID)
	if err != nil {
		return nil, err
	}
	decrypted.Source = evt
	return decrypted, nil
}

type OlmEventKeys struct {
	Ed25519 id.Ed25519 `json:"ed25519"`
}

func (mach *OlmMachine) decryptAndParseOlmCiphertext(sender id.UserID, senderKey id.SenderKey, olmType id.OlmMsgType, ciphertext string, traceID string) (*DecryptedOlmEvent, error) {
	if olmType != id.OlmMsgTypePreKey && olmType != id.OlmMsgTypeMsg {
		return nil, UnsupportedOlmMessageType
	}

	endTimeTrace := mach.timeTrace("decrypting olm ciphertext", traceID, 5*time.Second)
	plaintext, err := mach.tryDecryptOlmCiphertext(sender, senderKey, olmType, ciphertext, traceID)
	endTimeTrace()
	if err != nil {
		return nil, err
	}

	defer mach.timeTrace("parsing decrypted olm event", traceID, time.Second)()

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
	if err != nil && !errors.Is(err, event.ErrUnsupportedContentType) {
		return nil, fmt.Errorf("failed to parse content of olm payload event: %w", err)
	}

	olmEvt.SenderKey = senderKey

	return &olmEvt, nil
}

func (mach *OlmMachine) tryDecryptOlmCiphertext(sender id.UserID, senderKey id.SenderKey, olmType id.OlmMsgType, ciphertext string, traceID string) ([]byte, error) {
	endTimeTrace := mach.timeTrace("waiting for olm lock", traceID, 5*time.Second)
	mach.olmLock.Lock()
	endTimeTrace()
	defer mach.olmLock.Unlock()

	plaintext, err := mach.tryDecryptOlmCiphertextWithExistingSession(senderKey, olmType, ciphertext, traceID)
	if err != nil {
		if err == DecryptionFailedWithMatchingSession {
			mach.Log.Warn("Found matching session yet decryption failed for sender %s with key %s", sender, senderKey)
			go mach.unwedgeDevice(sender, senderKey)
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
		go mach.unwedgeDevice(sender, senderKey)
		return nil, DecryptionFailedForNormalMessage
	}

	mach.Log.Trace("Trying to create inbound session for %s/%s", sender, senderKey)
	endTimeTrace = mach.timeTrace("creating inbound olm session", traceID, time.Second)
	session, err := mach.createInboundSession(senderKey, ciphertext)
	endTimeTrace()
	if err != nil {
		go mach.unwedgeDevice(sender, senderKey)
		return nil, fmt.Errorf("failed to create new session from prekey message: %w", err)
	}
	mach.Log.Debug("Created inbound olm session %s for %s/%s: %s", session.ID(), sender, senderKey, session.Describe())

	endTimeTrace = mach.timeTrace(fmt.Sprintf("decrypting prekey olm message with %s/%s", senderKey, session.ID()), traceID, time.Second)
	plaintext, err = session.Decrypt(ciphertext, olmType)
	endTimeTrace()
	if err != nil {
		go mach.unwedgeDevice(sender, senderKey)
		return nil, fmt.Errorf("failed to decrypt olm event with session created from prekey message: %w", err)
	}

	endTimeTrace = mach.timeTrace(fmt.Sprintf("updating new session %s/%s in database", senderKey, session.ID()), traceID, time.Second)
	err = mach.CryptoStore.UpdateSession(senderKey, session)
	endTimeTrace()
	if err != nil {
		mach.Log.Warn("Failed to update new olm session in crypto store after decrypting: %v", err)
	}
	return plaintext, nil
}

func (mach *OlmMachine) tryDecryptOlmCiphertextWithExistingSession(senderKey id.SenderKey, olmType id.OlmMsgType, ciphertext string, traceID string) ([]byte, error) {
	endTimeTrace := mach.timeTrace(fmt.Sprintf("getting sessions with %s", senderKey), traceID, time.Second)
	sessions, err := mach.CryptoStore.GetSessions(senderKey)
	endTimeTrace()
	if err != nil {
		return nil, fmt.Errorf("failed to get session for %s: %w", senderKey, err)
	}

	for _, session := range sessions {
		if olmType == id.OlmMsgTypePreKey {
			endTimeTrace = mach.timeTrace(fmt.Sprintf("checking if prekey olm message matches session %s/%s", senderKey, session.ID()), traceID, time.Second)
			matches, err := session.Internal.MatchesInboundSession(ciphertext)
			endTimeTrace()
			if err != nil {
				return nil, fmt.Errorf("failed to check if ciphertext matches inbound session: %w", err)
			} else if !matches {
				continue
			}
		}
		mach.Log.Trace("Trying to decrypt olm message from %s with session %s: %s", senderKey, session.ID(), session.Describe())
		endTimeTrace = mach.timeTrace(fmt.Sprintf("decrypting olm message with %s/%s", senderKey, session.ID()), traceID, time.Second)
		plaintext, err := session.Decrypt(ciphertext, olmType)
		endTimeTrace()
		if err != nil {
			if olmType == id.OlmMsgTypePreKey {
				return nil, DecryptionFailedWithMatchingSession
			}
		} else {
			endTimeTrace = mach.timeTrace(fmt.Sprintf("updating session %s/%s in database", senderKey, session.ID()), traceID, time.Second)
			err = mach.CryptoStore.UpdateSession(senderKey, session)
			endTimeTrace()
			if err != nil {
				mach.Log.Warn("Failed to update olm session in crypto store after decrypting: %v", err)
			}
			mach.Log.Trace("Decrypted olm message from %s with session %s", senderKey, session.ID())
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

const MinUnwedgeInterval = 1 * time.Hour

func (mach *OlmMachine) unwedgeDevice(sender id.UserID, senderKey id.SenderKey) {
	mach.recentlyUnwedgedLock.Lock()
	prevUnwedge, ok := mach.recentlyUnwedged[senderKey]
	delta := time.Now().Sub(prevUnwedge)
	if ok && delta < MinUnwedgeInterval {
		mach.Log.Debug("Not creating new Olm session with %s/%s, previous recreation was %s ago", sender, senderKey, delta)
		mach.recentlyUnwedgedLock.Unlock()
		return
	}
	mach.recentlyUnwedged[senderKey] = time.Now()
	mach.recentlyUnwedgedLock.Unlock()

	deviceIdentity, err := mach.GetOrFetchDeviceByKey(sender, senderKey)
	if err != nil {
		mach.Log.Error("Failed to find device info by identity key: %v", err)
		return
	} else if deviceIdentity == nil {
		mach.Log.Warn("Didn't find identity of %s/%s, can't unwedge session", sender, senderKey)
		return
	}

	mach.Log.Debug("Creating new Olm session with %s/%s (key: %s)", sender, deviceIdentity.DeviceID, senderKey)
	mach.devicesToUnwedgeLock.Lock()
	mach.devicesToUnwedge[senderKey] = true
	mach.devicesToUnwedgeLock.Unlock()
	err = mach.SendEncryptedToDevice(deviceIdentity, event.ToDeviceDummy, event.Content{})
	if err != nil {
		mach.Log.Error("Failed to send dummy event to unwedge session with %s/%s: %v", sender, senderKey, err)
	}
}
