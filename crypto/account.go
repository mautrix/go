// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/crypto/olm"
	"github.com/element-hq/mautrix-go/id"
)

type OlmAccount struct {
	Internal    olm.Account
	signingKey  id.SigningKey
	identityKey id.IdentityKey
	Shared      bool
}

func NewOlmAccount() *OlmAccount {
	return &OlmAccount{
		Internal: *olm.NewAccount(),
	}
}

func (account *OlmAccount) Keys() (id.SigningKey, id.IdentityKey) {
	if len(account.signingKey) == 0 || len(account.identityKey) == 0 {
		account.signingKey, account.identityKey = account.Internal.IdentityKeys()
	}
	return account.signingKey, account.identityKey
}

func (account *OlmAccount) SigningKey() id.SigningKey {
	if len(account.signingKey) == 0 {
		account.signingKey, account.identityKey = account.Internal.IdentityKeys()
	}
	return account.signingKey
}

func (account *OlmAccount) IdentityKey() id.IdentityKey {
	if len(account.identityKey) == 0 {
		account.signingKey, account.identityKey = account.Internal.IdentityKeys()
	}
	return account.identityKey
}

func (account *OlmAccount) getInitialKeys(userID id.UserID, deviceID id.DeviceID) *mautrix.DeviceKeys {
	deviceKeys := &mautrix.DeviceKeys{
		UserID:     userID,
		DeviceID:   deviceID,
		Algorithms: []id.Algorithm{id.AlgorithmMegolmV1, id.AlgorithmOlmV1},
		Keys: map[id.DeviceKeyID]string{
			id.NewDeviceKeyID(id.KeyAlgorithmCurve25519, deviceID): string(account.IdentityKey()),
			id.NewDeviceKeyID(id.KeyAlgorithmEd25519, deviceID):    string(account.SigningKey()),
		},
	}

	signature, err := account.Internal.SignJSON(deviceKeys)
	if err != nil {
		panic(err)
	}

	deviceKeys.Signatures = mautrix.Signatures{
		userID: {
			id.NewKeyID(id.KeyAlgorithmEd25519, deviceID.String()): signature,
		},
	}
	return deviceKeys
}

func (account *OlmAccount) getOneTimeKeys(userID id.UserID, deviceID id.DeviceID, currentOTKCount int) map[id.KeyID]mautrix.OneTimeKey {
	newCount := int(account.Internal.MaxNumberOfOneTimeKeys()/2) - currentOTKCount
	if newCount > 0 {
		account.Internal.GenOneTimeKeys(uint(newCount))
	}
	oneTimeKeys := make(map[id.KeyID]mautrix.OneTimeKey)
	for keyID, key := range account.Internal.OneTimeKeys() {
		key := mautrix.OneTimeKey{Key: key}
		signature, _ := account.Internal.SignJSON(key)
		key.Signatures = mautrix.Signatures{
			userID: {
				id.NewKeyID(id.KeyAlgorithmEd25519, deviceID.String()): signature,
			},
		}
		key.IsSigned = true
		oneTimeKeys[id.NewKeyID(id.KeyAlgorithmSignedCurve25519, keyID)] = key
	}
	account.Internal.MarkKeysAsPublished()
	return oneTimeKeys
}
