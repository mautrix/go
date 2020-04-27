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

var (
	NoOneTimeKeyReceived = errors.New("no one-time key received")
	InvalidOTKSignature  = errors.New("invalid signature on one-time key")
)

func (mach *OlmMachine) encryptOlmEvent(session *OlmSession, recipient *DeviceIdentity, evtType event.Type, content event.Content) *event.EncryptedEventContent {
	selfSigningKey, selfIdentityKey := mach.account.IdentityKeys()
	evt := &OlmEvent{
		Sender:        mach.client.UserID,
		SenderDevice:  mach.client.DeviceID,
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
	// TODO this probably needs to be done somewhere
	//sess, err := mach.store.GetLatestSession(recipientKey)
	//if err != nil {
	//	return nil, errors.Wrap(err, "failed to get session")
	//}
	//if sess == nil {
	//	sess, err = mach.createOutboundSession(recipient, recipientKey)
	//	if err != nil {
	//		return nil, errors.Wrap(err, "failed to create session")
	//	}
	//}
}

func (mach *OlmMachine) createOutboundSession(userID id.UserID, deviceID id.DeviceID, identityKey id.Curve25519, signingKey id.Ed25519) (*OlmSession, error) {
	resp, err := mach.client.ClaimKeys(&mautrix.ReqClaimKeys{
		OneTimeKeys: mautrix.OneTimeKeysRequest{userID: {deviceID: id.KeyAlgorithmSignedCurve25519}},
		Timeout:     10 * 1000,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to claim keys")
	}
	deviceKeyID := id.NewDeviceKeyID(id.KeyAlgorithmSignedCurve25519, deviceID)
	oneTimeKey, ok := resp.OneTimeKeys[userID][deviceKeyID]
	if !ok {
		return nil, NoOneTimeKeyReceived
	}
	ok, err = olm.VerifySignatureJSON(oneTimeKey, userID, deviceID, signingKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify signature")
	} else if !ok {
		return nil, InvalidOTKSignature
	}
	sess, err := mach.account.NewOutboundSession(identityKey, oneTimeKey.Key)
	if err != nil {
		return nil, err
	}
	wrapped := wrapSession(sess)
	return wrapped, mach.store.AddSession(identityKey, wrapped)
}
