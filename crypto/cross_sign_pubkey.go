// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

type CrossSigningPublicKeysCache struct {
	MasterKey      id.Ed25519
	SelfSigningKey id.Ed25519
	UserSigningKey id.Ed25519
}

func (mach *OlmMachine) GetOwnCrossSigningPublicKeys() *CrossSigningPublicKeysCache {
	if mach.crossSigningPubkeys != nil {
		return mach.crossSigningPubkeys
	}
	if mach.CrossSigningKeys != nil {
		mach.crossSigningPubkeys = mach.CrossSigningKeys.PublicKeys()
		return mach.crossSigningPubkeys
	}
	cspk, err := mach.GetCrossSigningPublicKeys(mach.Client.UserID)
	if err != nil {
		mach.Log.Error("Failed to get own cross-signing public keys: %v", err)
		return nil
	}
	mach.crossSigningPubkeys = cspk
	return mach.crossSigningPubkeys
}

func (mach *OlmMachine) GetCrossSigningPublicKeys(userID id.UserID) (*CrossSigningPublicKeysCache, error) {
	dbKeys, err := mach.CryptoStore.GetCrossSigningKeys(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys from database: %w", err)
	}
	if len(dbKeys) > 0 {
		masterKey, ok := dbKeys[id.XSUsageMaster]
		if ok {
			selfSigning, _ := dbKeys[id.XSUsageSelfSigning]
			userSigning, _ := dbKeys[id.XSUsageUserSigning]
			return &CrossSigningPublicKeysCache{
				MasterKey:      masterKey,
				SelfSigningKey: selfSigning,
				UserSigningKey: userSigning,
			}, nil
		}
	}

	keys, err := mach.Client.QueryKeys(&mautrix.ReqQueryKeys{
		DeviceKeys: mautrix.DeviceKeysRequest{
			userID: mautrix.DeviceIDList{},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}

	var cspk CrossSigningPublicKeysCache

	masterKeys, ok := keys.MasterKeys[userID]
	if !ok {
		return nil, nil
	}
	cspk.MasterKey = masterKeys.FirstKey()

	selfSigningKeys, ok := keys.SelfSigningKeys[userID]
	if !ok {
		return nil, nil
	}
	cspk.SelfSigningKey = selfSigningKeys.FirstKey()

	userSigningKeys, ok := keys.UserSigningKeys[userID]
	if ok {
		cspk.UserSigningKey = userSigningKeys.FirstKey()
	}
	return &cspk, nil
}
