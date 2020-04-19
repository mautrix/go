// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/olm"
)

type OlmMachine struct {
	UserID   id.UserID
	DeviceID id.DeviceID
	Store    Store

	account *olm.Account
}

func NewOlmMachine(userID id.UserID, deviceID id.DeviceID, store Store) *OlmMachine {
	return &OlmMachine{
		UserID:   userID,
		DeviceID: deviceID,
		Store:    store,
	}
}

func (mach *OlmMachine) Load() {
	mach.account = mach.Store.LoadAccount()
	if mach.account == nil {
		mach.account = olm.NewAccount()
	}
}

// NewOneTimeKeys generates new one-time keys and returns a key upload request.
// If no new one-time keys are needed, this returns nil. In that case, the upload request should not be made.
func (mach *OlmMachine) NewOneTimeKeys() *mautrix.ReqUploadKeys {
	otks := mach.getOneTimeKeys()
	if len(otks) == 0 {
		return nil
	}
	return &mautrix.ReqUploadKeys{
		OneTimeKeys: otks,
	}
}

// InitialKeys returns the initial key upload request, including signed device keys and unsigned one-time keys.
func (mach *OlmMachine) InitialKeys() (*mautrix.ReqUploadKeys, error) {
	ed, curve := mach.account.IdentityKeys()
	deviceKeys := &mautrix.DeviceKeys{
		UserID:     mach.UserID,
		DeviceID:   mach.DeviceID,
		Algorithms: []string{string(olm.AlgorithmMegolmV1)},
		Keys: map[id.DeviceKeyID]string{
			id.NewDeviceKeyID("curve25519", mach.DeviceID): string(curve),
			id.NewDeviceKeyID("ed25519", mach.DeviceID):    string(ed),
		},
		Signatures: map[id.UserID]map[id.DeviceKeyID]string{
			mach.UserID: {
				// This is filled below.
			},
		},
	}

	signature, err := mach.account.SignJSON(deviceKeys)
	if err != nil {
		return nil, err
	}

	deviceKeys.Signatures[mach.UserID][id.NewDeviceKeyID("ed25519", mach.DeviceID)] = signature

	return &mautrix.ReqUploadKeys{
		DeviceKeys:  deviceKeys,
		OneTimeKeys: mach.getOneTimeKeys(),
	}, nil
}

func (mach *OlmMachine) getOneTimeKeys() map[id.KeyID]string {
	mach.account.GenOneTimeKeys(mach.account.MaxNumberOfOneTimeKeys() / 2)
	oneTimeKeys := make(map[id.KeyID]string)
	for keyID, key := range mach.account.OneTimeKeys().Curve25519 {
		oneTimeKeys[id.NewKeyID("curve25519", keyID)] = string(key)
	}
	mach.account.MarkKeysAsPublished()
	return oneTimeKeys
}
