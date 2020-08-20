// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
	"maunium.net/go/mautrix/crypto/utils"
)

// AccountDataKeyType is the type of account data cross-signing keys that can be stored on SSSS.
type AccountDataKeyType string

// AccountDataDefaultKeyType is the type for fetching the default key's ID.
var AccountDataDefaultKeyType AccountDataKeyType = "m.secret_storage.default_key"

// AccountDataMasterKeyType is the type for master cross-signing keys.
var AccountDataMasterKeyType AccountDataKeyType = "m.cross_signing.master"

// AccountDataUserSigningKeyType is the type for user signing keys.
var AccountDataUserSigningKeyType AccountDataKeyType = "m.cross_signing.user_signing"

// AccountDataSelfSigningKeyType is the type for self signing keys.
var AccountDataSelfSigningKeyType AccountDataKeyType = "m.cross_signing.self_signing"

// SSSSAlgorithm is the type for algorithms used in SSSS.
type SSSSAlgorithm string

// SSSSAlgorithmPBKDF2 is the algorithm used for deriving a key from a SSSS passphrase.
var SSSSAlgorithmPBKDF2 SSSSAlgorithm = "m.pbkdf2"

// SSSSAlgorithmAESHMACSHA2 is the algorithm used for encrypting and verifying secrets stored on SSSS.
var SSSSAlgorithmAESHMACSHA2 SSSSAlgorithm = "m.secret_storage.v1.aes-hmac-sha2"

type ssssPassphraseData struct {
	Algorithm  SSSSAlgorithm `json:"algorithm"`
	Iterations int           `json:"iterations"`
	Salt       string        `json:"salt"`
	Bits       int           `json:"bits"`
}

type ssssKeyData struct {
	Algorithm  SSSSAlgorithm       `json:"algorithm"`
	IV         string              `json:"iv"`
	MAC        string              `json:"mac"`
	Passphrase *ssssPassphraseData `json:"passphrase,omitempty"`
}

type ssssEncryptedKeyData struct {
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv"`
	MAC        string `json:"mac"`
}

type ssssEncryptedData struct {
	Encrypted map[string]ssssEncryptedKeyData `json:"encrypted"`
}

func (mach *OlmMachine) getDefaultKeyID() (string, error) {
	data, err := mach.Client.GetAccountData(string(AccountDataDefaultKeyType))
	if err != nil {
		return "", err
	}
	keyID, ok := data["key"]
	if !ok {
		return "", errors.New("Could not get default key ID")
	}
	return keyID.(string), nil
}

func (mach *OlmMachine) retrieveDecryptSSSSKey(keyName AccountDataKeyType, keyID string, ssssKey []byte) ([utils.AESCTRKeyLength]byte, error) {
	var decryptedKey [utils.AESCTRKeyLength]byte
	var encData ssssEncryptedData
	data, err := mach.Client.GetAccountData(string(keyName))
	if err != nil {
		return decryptedKey, err
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return decryptedKey, err
	}
	if err := json.Unmarshal(bytes, &encData); err != nil {
		return decryptedKey, err
	}

	keyEncData, ok := encData.Encrypted[keyID]
	if !ok {
		return decryptedKey, errors.New("Encrypted data for this key not found")
	}

	var ivBytes [utils.AESCTRIVLength]byte
	decodedIV, _ := base64.StdEncoding.DecodeString(keyEncData.IV)
	copy(ivBytes[:], decodedIV)

	ciphertextBytes, err := base64.StdEncoding.DecodeString(keyEncData.Ciphertext)
	if err != nil {
		return decryptedKey, err
	}

	aesKey, hmacKey := utils.DeriveKeysSHA256(ssssKey, string(keyName))

	calcMac := utils.HMACSHA256B64(ciphertextBytes, hmacKey)
	if strings.ReplaceAll(keyEncData.MAC, "=", "") != strings.ReplaceAll(calcMac, "=", "") {
		return decryptedKey, errors.New("Key data MAC mismatch")
	}

	decrypted := utils.XorA256CTR(ciphertextBytes, aesKey, ivBytes)
	copy(decryptedKey[:], decrypted)

	return decryptedKey, nil
}

func (mach *OlmMachine) retrieveSSSSKeyData(keyID string) (*ssssKeyData, error) {
	var keyData ssssKeyData
	data, err := mach.Client.GetAccountData("m.secret_storage.key." + keyID)
	if err != nil {
		return nil, err
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(bytes, &keyData); err != nil {
		return nil, err
	}

	return &keyData, nil
}

func verifySSSSKey(ssssKey []byte, iv, mac string) error {
	aesKey, hmacKey := utils.DeriveKeysSHA256(ssssKey, "")

	var ivBytes [utils.AESCTRIVLength]byte
	decodedIV, _ := base64.StdEncoding.DecodeString(iv)
	copy(ivBytes[:], decodedIV)

	var zeroBytes [utils.AESCTRKeyLength]byte
	cipher := utils.XorA256CTR(zeroBytes[:], aesKey, ivBytes)

	calcMac := utils.HMACSHA256B64(cipher, hmacKey)

	if strings.ReplaceAll(mac, "=", "") != strings.ReplaceAll(calcMac, "=", "") {
		return errors.New("Storage key MAC mismatch")
	}

	return nil
}

// RetrieveCrossSigningKeysWithPassphrase retrieves the cross-signing keys from SSSS using the given passphrase to decrypt them.
func (mach *OlmMachine) RetrieveCrossSigningKeysWithPassphrase(passphrase string) error {
	keyID, err := mach.getDefaultKeyID()
	if err != nil {
		return err
	}
	mach.Log.Debug("Default SSSS key ID: %v", keyID)

	keyData, err := mach.retrieveSSSSKeyData(keyID)
	if err != nil {
		return err
	}

	if keyData.Passphrase == nil {
		return errors.New("No passphrase data in default key")
	}

	if keyData.Passphrase.Algorithm != SSSSAlgorithmPBKDF2 {
		return errors.New("Unexpected passphrase KDF algorithm")
	}

	bits := 256
	if keyData.Passphrase.Bits != 0 {
		bits = keyData.Passphrase.Bits
	}

	ssssKey := utils.PBKDF2SHA512([]byte(passphrase), []byte(keyData.Passphrase.Salt), keyData.Passphrase.Iterations, bits)

	if err := verifySSSSKey(ssssKey, keyData.IV, keyData.MAC); err != nil {
		return err
	}

	mach.Log.Debug("Retrieved and verified SSSS key from passphrase")

	masterKey, err := mach.retrieveDecryptSSSSKey(AccountDataMasterKeyType, keyID, ssssKey)
	if err != nil {
		return err
	}
	selfSignKey, err := mach.retrieveDecryptSSSSKey(AccountDataSelfSigningKeyType, keyID, ssssKey)
	if err != nil {
		return err
	}
	userSignKey, err := mach.retrieveDecryptSSSSKey(AccountDataUserSigningKeyType, keyID, ssssKey)
	if err != nil {
		return err
	}

	mach.Log.Error("keys %v %v %v", masterKey, selfSignKey, userSignKey)

	return nil
}

// RetrieveCrossSigningKeysWithRecoveryKey retrieves the cross-signing keys from SSSS using the given recovery key to decrypt them.
func (mach *OlmMachine) RetrieveCrossSigningKeysWithRecoveryKey(recoveryKey string) error {
	keyID, err := mach.getDefaultKeyID()
	if err != nil {
		return err
	}
	mach.Log.Debug("Default SSSS key ID: %v", keyID)

	keyData, err := mach.retrieveSSSSKeyData(keyID)
	if err != nil {
		return err
	}

	ssssKey := utils.DecodeBase58RecoveryKey(recoveryKey)

	if err := verifySSSSKey(ssssKey[:], keyData.IV, keyData.MAC); err != nil {
		return err
	}

	mach.Log.Debug("Retrieved and verified SSSS key from recovery key")

	masterKey, err := mach.retrieveDecryptSSSSKey(AccountDataMasterKeyType, keyID, ssssKey[:])
	if err != nil {
		return err
	}
	selfSignKey, err := mach.retrieveDecryptSSSSKey(AccountDataSelfSigningKeyType, keyID, ssssKey[:])
	if err != nil {
		return err
	}
	userSignKey, err := mach.retrieveDecryptSSSSKey(AccountDataUserSigningKeyType, keyID, ssssKey[:])
	if err != nil {
		return err
	}

	mach.Log.Error("keys %v %v %v", masterKey, selfSignKey, userSignKey)

	return nil
}
