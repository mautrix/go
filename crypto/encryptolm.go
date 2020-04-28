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
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (mach *OlmMachine) encryptOlmEvent(session *OlmSession, recipient *DeviceIdentity, evtType event.Type, content event.Content) *event.EncryptedEventContent {
	selfSigningKey, selfIdentityKey := mach.account.IdentityKeys()
	evt := &OlmEvent{
		Sender:        mach.Client.UserID,
		SenderDevice:  mach.Client.DeviceID,
		Keys:          OlmEventKeys{Ed25519: selfSigningKey},
		Recipient:     recipient.UserID,
		RecipientKeys: OlmEventKeys{Ed25519: recipient.SigningKey},
		Type:          evtType,
		Content:       content,
	}
	plaintext, err := json.Marshal(evt)
	if err != nil {
		panic(err)
	}
	msgType, ciphertext := session.Encrypt(plaintext)
	return &event.EncryptedEventContent{
		Algorithm: id.AlgorithmOlmV1,
		SenderKey: selfIdentityKey,
		OlmCiphertext: event.OlmCiphertexts{
			recipient.IdentityKey: {
				Type: msgType,
				Body: string(ciphertext),
			},
		},
	}
}

func (mach *OlmMachine) createOutboundSessions(input map[id.UserID]map[id.DeviceID]*DeviceIdentity) error {
	request := make(mautrix.OneTimeKeysRequest)
	for userID, devices := range input {
		request[userID] = make(map[id.DeviceID]id.KeyAlgorithm)
		for deviceID, identity := range devices {
			if !mach.Store.HasSession(identity.IdentityKey) {
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
		return errors.Wrap(err, "failed to claim keys")
	}
	dat, _ := json.MarshalIndent(resp, "", "  ")
	mach.Log.Debug("%s", string(dat))
	for userID, user := range resp.OneTimeKeys {
		for deviceID, oneTimeKeys := range user {
			var oneTimeKey mautrix.OneTimeKey
			var keyID id.KeyID
			for keyID, oneTimeKey = range oneTimeKeys {
				break
			}
			keyAlg, _ := keyID.Parse()
			if keyAlg != id.KeyAlgorithmSignedCurve25519 {
				mach.Log.Warn("Unexpected key ID algorithm in one-time key response for %s of %s: %s", deviceID, userID, keyID)
				continue
			}
			identity := input[userID][deviceID]
			if ok, err := olm.VerifySignatureJSON(oneTimeKey, userID, deviceID, identity.SigningKey); err != nil {
				mach.Log.Error("Failed to verify signature for %s of %s: %v", deviceID, userID, err)
			} else if !ok {
				mach.Log.Warn("Invalid signature for %s of %s", deviceID, userID)
			} else if sess, err := mach.account.NewOutboundSession(identity.IdentityKey, oneTimeKey.Key); err != nil {
				mach.Log.Error("Failed to create outbound session for %s of %s: %v", deviceID, userID, err)
			} else {
				wrapped := wrapSession(sess)
				err = mach.Store.AddSession(identity.IdentityKey, wrapped)
				if err != nil {
					mach.Log.Error("Failed to store created session for %s of %s: %v", deviceID, userID, err)
				}
			}
		}
	}
	return nil
}
