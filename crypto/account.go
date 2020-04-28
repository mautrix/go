// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

type OlmAccount struct {
	Internal olm.Account
	Shared   bool
}

func (account *OlmAccount) getInitialKeys(userID id.UserID, deviceID id.DeviceID) *mautrix.DeviceKeys {
	ed, curve := account.Internal.IdentityKeys()
	deviceKeys := &mautrix.DeviceKeys{
		UserID:     userID,
		DeviceID:   deviceID,
		Algorithms: []id.Algorithm{id.AlgorithmMegolmV1, id.AlgorithmOlmV1},
		Keys: map[id.DeviceKeyID]string{
			id.NewDeviceKeyID(id.KeyAlgorithmCurve25519, deviceID): string(curve),
			id.NewDeviceKeyID(id.KeyAlgorithmEd25519, deviceID):    string(ed),
		},
	}

	signature, err := account.Internal.SignJSON(deviceKeys)
	if err != nil {
		panic(err)
	}

	deviceKeys.Signatures = mautrix.Signatures{
		userID: {
			id.NewDeviceKeyID(id.KeyAlgorithmEd25519, deviceID): signature,
		},
	}
	return deviceKeys
}

func (account *OlmAccount) getOneTimeKeys(userID id.UserID, deviceID id.DeviceID) map[id.KeyID]mautrix.OneTimeKey {
	account.Internal.GenOneTimeKeys(account.Internal.MaxNumberOfOneTimeKeys() / 3 * 2)
	oneTimeKeys := make(map[id.KeyID]mautrix.OneTimeKey)
	// TODO do we need unsigned curve25519 one-time keys at all?
	//      this just signs all of them
	for keyID, key := range account.Internal.OneTimeKeys() {
		key := mautrix.OneTimeKey{Key: key}
		signature, _ := account.Internal.SignJSON(key)
		key.Signatures = mautrix.Signatures{
			userID: {
				id.NewDeviceKeyID(id.KeyAlgorithmEd25519, deviceID): signature,
			},
		}
		key.IsSigned = true
		oneTimeKeys[id.NewKeyID(id.KeyAlgorithmSignedCurve25519, keyID)] = key
	}
	account.Internal.MarkKeysAsPublished()
	return oneTimeKeys
}
