// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/json"

	"github.com/tidwall/sjson"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"
)

type OlmAccount struct {
	Internal         olm.Account
	signingKey       id.SigningKey
	identityKey      id.IdentityKey
	Shared           bool
	KeyBackupVersion id.KeyBackupVersion
}

func NewOlmAccount() *OlmAccount {
	account, err := olm.NewAccount()
	if err != nil {
		panic(err)
	}
	return &OlmAccount{
		Internal: account,
	}
}

func (account *OlmAccount) Keys() (id.SigningKey, id.IdentityKey) {
	if len(account.signingKey) == 0 || len(account.identityKey) == 0 {
		var err error
		account.signingKey, account.identityKey, err = account.Internal.IdentityKeys()
		if err != nil {
			panic(err)
		}
	}
	return account.signingKey, account.identityKey
}

func (account *OlmAccount) SigningKey() id.SigningKey {
	if len(account.signingKey) == 0 {
		var err error
		account.signingKey, account.identityKey, err = account.Internal.IdentityKeys()
		if err != nil {
			panic(err)
		}
	}
	return account.signingKey
}

func (account *OlmAccount) IdentityKey() id.IdentityKey {
	if len(account.identityKey) == 0 {
		var err error
		account.signingKey, account.identityKey, err = account.Internal.IdentityKeys()
		if err != nil {
			panic(err)
		}
	}
	return account.identityKey
}

// SignJSON signs the given JSON object following the Matrix specification:
// https://matrix.org/docs/spec/appendices#signing-json
func (account *OlmAccount) SignJSON(obj any) (string, error) {
	objJSON, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	objJSON, _ = sjson.DeleteBytes(objJSON, "unsigned")
	objJSON, _ = sjson.DeleteBytes(objJSON, "signatures")
	signed, err := account.Internal.Sign(canonicaljson.CanonicalJSONAssumeValid(objJSON))
	return string(signed), err
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

	signature, err := account.SignJSON(deviceKeys)
	if err != nil {
		panic(err)
	}

	deviceKeys.Signatures = signatures.NewSingleSignature(userID, id.KeyAlgorithmEd25519, deviceID.String(), signature)
	return deviceKeys
}

func (account *OlmAccount) getOneTimeKeys(userID id.UserID, deviceID id.DeviceID, currentOTKCount int) map[id.KeyID]mautrix.OneTimeKey {
	newCount := int(account.Internal.MaxNumberOfOneTimeKeys()/2) - currentOTKCount
	if newCount > 0 {
		account.Internal.GenOneTimeKeys(uint(newCount))
	}
	oneTimeKeys := make(map[id.KeyID]mautrix.OneTimeKey)
	internalKeys, err := account.Internal.OneTimeKeys()
	if err != nil {
		panic(err)
	}
	for keyID, key := range internalKeys {
		key := mautrix.OneTimeKey{Key: key}
		signature, _ := account.SignJSON(key)
		key.Signatures = signatures.NewSingleSignature(userID, id.KeyAlgorithmEd25519, deviceID.String(), signature)
		key.IsSigned = true
		oneTimeKeys[id.NewKeyID(id.KeyAlgorithmSignedCurve25519, keyID)] = key
	}
	return oneTimeKeys
}
