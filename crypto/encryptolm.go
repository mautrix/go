// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/json"
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (mach *OlmMachine) encryptOlmEvent(session *OlmSession, recipient *id.Device, evtType event.Type, content event.Content) *event.EncryptedEventContent {
	evt := &DecryptedOlmEvent{
		Sender:        mach.Client.UserID,
		SenderDevice:  mach.Client.DeviceID,
		Keys:          OlmEventKeys{Ed25519: mach.account.SigningKey()},
		Recipient:     recipient.UserID,
		RecipientKeys: OlmEventKeys{Ed25519: recipient.SigningKey},
		Type:          evtType,
		Content:       content,
	}
	plaintext, err := json.Marshal(evt)
	if err != nil {
		panic(err)
	}
	mach.Log.Trace("Encrypting olm message for %s with session %s: %s", recipient.IdentityKey, session.ID(), session.Describe())
	msgType, ciphertext := session.Encrypt(plaintext)
	err = mach.CryptoStore.UpdateSession(recipient.IdentityKey, session)
	if err != nil {
		mach.Log.Warn("Failed to update olm session in crypto store after encrypting: %v", err)
	}
	return &event.EncryptedEventContent{
		Algorithm: id.AlgorithmOlmV1,
		SenderKey: mach.account.IdentityKey(),
		OlmCiphertext: event.OlmCiphertexts{
			recipient.IdentityKey: {
				Type: msgType,
				Body: string(ciphertext),
			},
		},
	}
}

func (mach *OlmMachine) shouldCreateNewSession(identityKey id.IdentityKey) bool {
	if !mach.CryptoStore.HasSession(identityKey) {
		return true
	}
	mach.devicesToUnwedgeLock.Lock()
	_, shouldUnwedge := mach.devicesToUnwedge[identityKey]
	if shouldUnwedge {
		delete(mach.devicesToUnwedge, identityKey)
	}
	mach.devicesToUnwedgeLock.Unlock()
	return shouldUnwedge
}

func (mach *OlmMachine) createOutboundSessions(input map[id.UserID]map[id.DeviceID]*id.Device) error {
	request := make(mautrix.OneTimeKeysRequest)
	for userID, devices := range input {
		request[userID] = make(map[id.DeviceID]id.KeyAlgorithm)
		for deviceID, identity := range devices {
			if mach.shouldCreateNewSession(identity.IdentityKey) {
				request[userID][deviceID] = id.KeyAlgorithmSignedCurve25519
			}
		}
		if len(request[userID]) == 0 {
			delete(request, userID)
		}
	}
	if len(request) == 0 {
		return nil
	}
	resp, err := mach.Client.ClaimKeys(&mautrix.ReqClaimKeys{
		OneTimeKeys: request,
		Timeout:     10 * 1000,
	})
	if err != nil {
		return fmt.Errorf("failed to claim keys: %w", err)
	}
	for userID, user := range resp.OneTimeKeys {
		for deviceID, oneTimeKeys := range user {
			var oneTimeKey mautrix.OneTimeKey
			var keyID id.KeyID
			for keyID, oneTimeKey = range oneTimeKeys {
				break
			}
			keyAlg, keyIndex := keyID.Parse()
			if keyAlg != id.KeyAlgorithmSignedCurve25519 {
				mach.Log.Warn("Unexpected key ID algorithm in one-time key response for %s of %s: %s", deviceID, userID, keyID)
				continue
			}
			identity := input[userID][deviceID]
			if ok, err := olm.VerifySignatureJSON(oneTimeKey, userID, deviceID.String(), identity.SigningKey); err != nil {
				mach.Log.Error("Failed to verify signature for %s of %s: %v", deviceID, userID, err)
			} else if !ok {
				mach.Log.Warn("Invalid signature for %s of %s", deviceID, userID)
			} else if sess, err := mach.account.Internal.NewOutboundSession(identity.IdentityKey, oneTimeKey.Key); err != nil {
				mach.Log.Error("Failed to create outbound session for %s of %s: %v", deviceID, userID, err)
			} else {
				wrapped := wrapSession(sess)
				err = mach.CryptoStore.AddSession(identity.IdentityKey, wrapped)
				if err != nil {
					mach.Log.Error("Failed to store created session for %s of %s: %v", deviceID, userID, err)
				} else {
					mach.Log.Debug("Created new Olm session with %s/%s (OTK ID: %s)", userID, deviceID, keyIndex)
				}
			}
		}
	}
	return nil
}
