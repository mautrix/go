// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/ssss"
	"maunium.net/go/mautrix/crypto/utils"
	"maunium.net/go/mautrix/event"
)

// FetchCrossSigningKeysFromSSSS fetches all the cross-signing keys from SSSS, decrypts them using the given key and stores them in the olm machine.
func (mach *OlmMachine) FetchCrossSigningKeysFromSSSS(key *ssss.Key) error {
	masterKey, err := mach.retrieveDecryptXSigningKey(event.AccountDataCrossSigningMaster, key)
	if err != nil {
		return err
	}
	selfSignKey, err := mach.retrieveDecryptXSigningKey(event.AccountDataCrossSigningSelf, key)
	if err != nil {
		return err
	}
	userSignKey, err := mach.retrieveDecryptXSigningKey(event.AccountDataCrossSigningUser, key)
	if err != nil {
		return err
	}

	return mach.ImportCrossSigningKeys(CrossSigningSeeds{
		MasterKey:      masterKey[:],
		SelfSigningKey: selfSignKey[:],
		UserSigningKey: userSignKey[:],
	})
}

// retrieveDecryptXSigningKey retrieves the requested cross-signing key from SSSS and decrypts it using the given SSSS key.
func (mach *OlmMachine) retrieveDecryptXSigningKey(keyName event.Type, key *ssss.Key) ([utils.AESCTRKeyLength]byte, error) {
	var decryptedKey [utils.AESCTRKeyLength]byte
	var encData ssss.EncryptedAccountDataEventContent

	// retrieve and parse the account data for this key type from SSSS
	err := mach.Client.GetAccountData(keyName.Type, &encData)
	if err != nil {
		return decryptedKey, err
	}

	decrypted, err := encData.Decrypt(keyName.Type, key)
	if err != nil {
		return decryptedKey, err
	}
	copy(decryptedKey[:], decrypted)
	return decryptedKey, nil
}

// GenerateAndUploadCrossSigningKeys generates a new key with all corresponding cross-signing keys.
//
// A passphrase can be provided to generate the SSSS key. If the passphrase is empty, a random key
// is used. The base58-formatted recovery key is the first return parameter.
//
// The account password of the user is required for uploading keys to the server.
func (mach *OlmMachine) GenerateAndUploadCrossSigningKeys(userPassword, passphrase string) (string, error) {
	key, err := mach.SSSS.GenerateAndUploadKey(passphrase)
	if err != nil {
		return "", fmt.Errorf("failed to generate and upload SSSS key: %w", err)
	}

	// generate the three cross-signing keys
	keysCache, err := mach.GenerateCrossSigningKeys()
	if err != nil {
		return "", err
	}

	recoveryKey := key.RecoveryKey()

	// Store the private keys in SSSS
	if err := mach.UploadCrossSigningKeysToSSSS(key, keysCache); err != nil {
		return recoveryKey, fmt.Errorf("failed to upload cross-signing keys to SSSS: %w", err)
	}

	// Publish cross-signing keys
	err = mach.PublishCrossSigningKeys(keysCache, func(uiResp *mautrix.RespUserInteractive) interface{} {
		return &mautrix.ReqUIAuthLogin{
			BaseAuthData: mautrix.BaseAuthData{
				Type:    mautrix.AuthTypePassword,
				Session: uiResp.Session,
			},
			User:     mach.Client.UserID.String(),
			Password: userPassword,
		}
	})
	if err != nil {
		return recoveryKey, fmt.Errorf("failed to publish cross-signing keys: %w", err)
	}

	err = mach.SSSS.SetDefaultKeyID(key.ID)
	if err != nil {
		return recoveryKey, fmt.Errorf("failed to mark %s as the default key: %w", key.ID, err)
	}

	return recoveryKey, nil
}

// UploadCrossSigningKeysToSSSS stores the given cross-signing keys on the server encrypted with the given key.
func (mach *OlmMachine) UploadCrossSigningKeysToSSSS(key *ssss.Key, keys *CrossSigningKeysCache) error {
	if err := mach.SSSS.SetEncryptedAccountData(event.AccountDataCrossSigningMaster, keys.MasterKey.Seed, key); err != nil {
		return err
	}
	if err := mach.SSSS.SetEncryptedAccountData(event.AccountDataCrossSigningSelf, keys.SelfSigningKey.Seed, key); err != nil {
		return err
	}
	if err := mach.SSSS.SetEncryptedAccountData(event.AccountDataCrossSigningUser, keys.UserSigningKey.Seed, key); err != nil {
		return err
	}
	return nil
}
