// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

// CrossSigningKeysCache holds the three cross-signing keys for the current user.
type CrossSigningKeysCache struct {
	MasterKey      *olm.PkSigning
	SelfSigningKey *olm.PkSigning
	UserSigningKey *olm.PkSigning
}

func (cskc *CrossSigningKeysCache) PublicKeys() *CrossSigningPublicKeysCache {
	return &CrossSigningPublicKeysCache{
		MasterKey:      cskc.MasterKey.PublicKey,
		SelfSigningKey: cskc.SelfSigningKey.PublicKey,
		UserSigningKey: cskc.UserSigningKey.PublicKey,
	}
}

type CrossSigningSeeds struct {
	MasterKey      []byte
	SelfSigningKey []byte
	UserSigningKey []byte
}

func (mach *OlmMachine) ExportCrossSigningKeys() CrossSigningSeeds {
	return CrossSigningSeeds{
		MasterKey:      mach.CrossSigningKeys.MasterKey.Seed,
		SelfSigningKey: mach.CrossSigningKeys.SelfSigningKey.Seed,
		UserSigningKey: mach.CrossSigningKeys.UserSigningKey.Seed,
	}
}

func (mach *OlmMachine) ImportCrossSigningKeys(keys CrossSigningSeeds) (err error) {
	var keysCache CrossSigningKeysCache
	if keysCache.MasterKey, err = olm.NewPkSigningFromSeed(keys.MasterKey); err != nil {
		return
	}
	if keysCache.SelfSigningKey, err = olm.NewPkSigningFromSeed(keys.SelfSigningKey); err != nil {
		return
	}
	if keysCache.UserSigningKey, err = olm.NewPkSigningFromSeed(keys.UserSigningKey); err != nil {
		return
	}

	mach.Log.Trace("Got cross-signing keys: Master `%v` Self-signing `%v` User-signing `%v`",
		keysCache.MasterKey.PublicKey, keysCache.SelfSigningKey.PublicKey, keysCache.UserSigningKey.PublicKey)

	mach.CrossSigningKeys = &keysCache
	mach.crossSigningPubkeys = keysCache.PublicKeys()
	return
}

// GenerateCrossSigningKeys generates new cross-signing keys.
func (mach *OlmMachine) GenerateCrossSigningKeys() (*CrossSigningKeysCache, error) {
	var keysCache CrossSigningKeysCache
	var err error
	if keysCache.MasterKey, err = olm.NewPkSigning(); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}
	if keysCache.SelfSigningKey, err = olm.NewPkSigning(); err != nil {
		return nil, fmt.Errorf("failed to generate self-signing key: %w", err)
	}
	if keysCache.UserSigningKey, err = olm.NewPkSigning(); err != nil {
		return nil, fmt.Errorf("failed to generate user-signing key: %w", err)
	}
	mach.Log.Debug("Generated cross-signing keys: Master: `%v` Self-signing: `%v` User-signing: `%v`",
		keysCache.MasterKey.PublicKey, keysCache.SelfSigningKey.PublicKey, keysCache.UserSigningKey.PublicKey)
	return &keysCache, nil
}

// PublishCrossSigningKeys signs and uploads the public keys of the given cross-signing keys to the server.
func (mach *OlmMachine) PublishCrossSigningKeys(keys *CrossSigningKeysCache, uiaCallback mautrix.UIACallback) error {
	userID := mach.Client.UserID
	masterKeyID := id.NewKeyID(id.KeyAlgorithmEd25519, keys.MasterKey.PublicKey.String())
	masterKey := mautrix.CrossSigningKeys{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
		Keys: map[id.KeyID]id.Ed25519{
			masterKeyID: keys.MasterKey.PublicKey,
		},
	}

	selfKey := mautrix.CrossSigningKeys{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageSelfSigning},
		Keys: map[id.KeyID]id.Ed25519{
			id.NewKeyID(id.KeyAlgorithmEd25519, keys.SelfSigningKey.PublicKey.String()): keys.SelfSigningKey.PublicKey,
		},
	}
	selfSig, err := keys.MasterKey.SignJSON(selfKey)
	if err != nil {
		return fmt.Errorf("failed to sign self-signing key: %w", err)
	}
	selfKey.Signatures = map[id.UserID]map[id.KeyID]string{
		userID: {
			masterKeyID: selfSig,
		},
	}

	userKey := mautrix.CrossSigningKeys{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageUserSigning},
		Keys: map[id.KeyID]id.Ed25519{
			id.NewKeyID(id.KeyAlgorithmEd25519, keys.UserSigningKey.PublicKey.String()): keys.UserSigningKey.PublicKey,
		},
	}
	userSig, err := keys.MasterKey.SignJSON(userKey)
	if err != nil {
		return fmt.Errorf("failed to sign user-signing key: %w", err)
	}
	userKey.Signatures = map[id.UserID]map[id.KeyID]string{
		userID: {
			masterKeyID: userSig,
		},
	}

	err = mach.Client.UploadCrossSigningKeys(&mautrix.UploadCrossSigningKeysReq{
		Master:      masterKey,
		SelfSigning: selfKey,
		UserSigning: userKey,
	}, uiaCallback)
	if err != nil {
		return err
	}

	mach.CrossSigningKeys = keys
	mach.crossSigningPubkeys = keys.PublicKeys()

	return nil
}
