// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/tidwall/sjson"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/crypto/goolm/account"
	"maunium.net/go/mautrix/crypto/libolm"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"
)

type OlmAccount struct {
	InternalLibolm   olm.Account
	InternalGoolm    olm.Account
	signingKey       id.SigningKey
	identityKey      id.IdentityKey
	Shared           bool
	KeyBackupVersion id.KeyBackupVersion
}

func NewOlmAccount() *OlmAccount {
	libolmAccount, err := libolm.NewAccount()
	if err != nil {
		panic(err)
	}
	pickled, err := libolmAccount.Pickle([]byte("key"))
	if err != nil {
		panic(err)
	}
	goolmAccount, err := account.AccountFromPickled(pickled, []byte("key"))
	if err != nil {
		panic(err)
	}
	return &OlmAccount{
		InternalLibolm: libolmAccount,
		InternalGoolm:  goolmAccount,
	}
}

func (account *OlmAccount) Keys() (id.SigningKey, id.IdentityKey) {
	if len(account.signingKey) == 0 || len(account.identityKey) == 0 {
		var err error
		account.signingKey, account.identityKey, err = account.InternalLibolm.IdentityKeys()
		if err != nil {
			panic(err)
		}
		goolmSigningKey, goolmIdentityKey, err := account.InternalGoolm.IdentityKeys()
		if err != nil {
			panic(err)
		}
		if account.signingKey != goolmSigningKey {
			panic("account signing keys not equal")
		}
		if account.identityKey != goolmIdentityKey {
			panic("account identity keys not equal")
		}
	}
	return account.signingKey, account.identityKey
}

func (account *OlmAccount) SigningKey() id.SigningKey {
	if len(account.signingKey) == 0 {
		var err error
		account.signingKey, account.identityKey, err = account.InternalLibolm.IdentityKeys()
		if err != nil {
			panic(err)
		}
		goolmSigningKey, goolmIdentityKey, err := account.InternalGoolm.IdentityKeys()
		if err != nil {
			panic(err)
		}
		if account.signingKey != goolmSigningKey {
			panic("account signing keys not equal")
		}
		if account.identityKey != goolmIdentityKey {
			panic("account identity keys not equal")
		}
	}
	return account.signingKey
}

func (account *OlmAccount) IdentityKey() id.IdentityKey {
	if len(account.identityKey) == 0 {
		var err error
		account.signingKey, account.identityKey, err = account.InternalLibolm.IdentityKeys()
		if err != nil {
			panic(err)
		}
		goolmSigningKey, goolmIdentityKey, err := account.InternalGoolm.IdentityKeys()
		if err != nil {
			panic(err)
		}
		if account.signingKey != goolmSigningKey {
			panic("account signing keys not equal")
		}
		if account.identityKey != goolmIdentityKey {
			panic("account identity keys not equal")
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
	signed, err := account.InternalLibolm.Sign(canonicaljson.CanonicalJSONAssumeValid(objJSON))
	goolmSigned, goolmErr := account.InternalGoolm.Sign(canonicaljson.CanonicalJSONAssumeValid(objJSON))
	if err != nil {
		if goolmErr == nil {
			panic("libolm errored, but goolm did not on account.SignJSON")
		}
	} else if !bytes.Equal(signed, goolmSigned) {
		panic("libolm and goolm signed are not equal in account.SignJSON")
	}
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

func (a *OlmAccount) getOneTimeKeys(userID id.UserID, deviceID id.DeviceID, currentOTKCount int) map[id.KeyID]mautrix.OneTimeKey {
	newCount := int(a.InternalLibolm.MaxNumberOfOneTimeKeys()/2) - currentOTKCount
	if newCount > 0 {
		a.InternalLibolm.GenOneTimeKeys(uint(newCount))

		pickled, err := a.InternalLibolm.Pickle([]byte("key"))
		if err != nil {
			panic(err)
		}
		a.InternalGoolm, err = account.AccountFromPickled(pickled, []byte("key"))
		if err != nil {
			panic(err)
		}
	}
	oneTimeKeys := make(map[id.KeyID]mautrix.OneTimeKey)
	internalKeys, err := a.InternalLibolm.OneTimeKeys()
	if err != nil {
		panic(err)
	}
	goolmInternalKeys, err := a.InternalGoolm.OneTimeKeys()
	if err != nil {
		panic(err)
	}
	for keyID, key := range internalKeys {
		if goolmInternalKeys[keyID] != key {
			panic(fmt.Sprintf("key %s not found in getOneTimeKeys", keyID))
		}

		key := mautrix.OneTimeKey{Key: key}
		signature, _ := a.SignJSON(key)
		key.Signatures = signatures.NewSingleSignature(userID, id.KeyAlgorithmEd25519, deviceID.String(), signature)
		key.IsSigned = true
		oneTimeKeys[id.NewKeyID(id.KeyAlgorithmSignedCurve25519, keyID)] = key
	}
	return oneTimeKeys
}
