// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/utils"
)

var (
	ErrNoDefaultKeyID                 = errors.New("could not find default key ID")
	ErrNoDefaultKeyAccountDataEvent   = fmt.Errorf("%w: no %s event in account data", ErrNoDefaultKeyID, AccountDataDefaultKeyType)
	ErrNoKeyFieldInAccountDataEvent   = fmt.Errorf("%w: missing key field in account data event", ErrNoDefaultKeyID)
	ErrKeyNotFound                    = errors.New("encrypted data for given key ID not found")
	ErrKeyDataMACMismatch             = errors.New("key data MAC mismatch")
	ErrStorageKeyMACMismatch          = errors.New("storage key MAC mismatch")
	ErrNoPassphrase                   = errors.New("no passphrase data has been set for the default key")
	ErrUnsupportedPassphraseAlgorithm = errors.New("unsupported passphrase KDF algorithm")
)

// AccountDataKeyType is the type of account data cross-signing keys that can be stored on SSSS.
type AccountDataKeyType string

var (
	// AccountDataDefaultKeyType is the type for fetching the default key's ID.
	AccountDataDefaultKeyType AccountDataKeyType = "m.secret_storage.default_key"
	// AccountDataMasterKeyType is the type for master cross-signing keys.
	AccountDataMasterKeyType AccountDataKeyType = "m.cross_signing.master"
	// AccountDataUserSigningKeyType is the type for user signing keys.
	AccountDataUserSigningKeyType AccountDataKeyType = "m.cross_signing.user_signing"
	// AccountDataSelfSigningKeyType is the type for self signing keys.
	AccountDataSelfSigningKeyType AccountDataKeyType = "m.cross_signing.self_signing"
)

// SSSSAlgorithm is the type for algorithms used in SSSS.
type SSSSAlgorithm string

var (
	// SSSSAlgorithmPBKDF2 is the algorithm used for deriving a key from an SSSS passphrase.
	SSSSAlgorithmPBKDF2 SSSSAlgorithm = "m.pbkdf2"
	// SSSSAlgorithmAESHMACSHA2 is the algorithm used for encrypting and verifying secrets stored on SSSS.
	SSSSAlgorithmAESHMACSHA2 SSSSAlgorithm = "m.secret_storage.v1.aes-hmac-sha2"
)

// CrossSigningKeysCache holds the three cross-signing keys for the current user.
type CrossSigningKeysCache struct {
	MasterKey      *olm.PkSigning
	SelfSigningKey *olm.PkSigning
	UserSigningKey *olm.PkSigning
}

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

// getDefaultKeyID retrieves the default key ID for this account from SSSS.
func (mach *OlmMachine) getDefaultKeyID() (string, error) {
	var data map[string]string
	err := mach.Client.GetAccountData(string(AccountDataDefaultKeyType), &data)
	if err != nil {
		// TODO add this check after HTTPError is moved or supports errors.Is
		// Currently it's commented out to avoid cyclic imports
		//if httpErr, ok := err.(*mautrix.HTTPError); ok && httpErr.RespError != nil && httpErr.RespError.ErrCode == "M_NOT_FOUND" {
		//	return "", ErrNoDefaultKeyAccountDataEvent
		//}
		return "", fmt.Errorf("failed to get default key account data from server: %w", err)
	}
	keyID, ok := data["key"]
	if !ok {
		return "", ErrNoKeyFieldInAccountDataEvent
	}
	return keyID, nil
}

// retrieveDecryptXSigningKey retrieves the requested cross-signing key from SSSS and decrypts it using the given SSSS key.
func (mach *OlmMachine) retrieveDecryptXSigningKey(keyName AccountDataKeyType, keyID string, ssssKey []byte) ([utils.AESCTRKeyLength]byte, error) {
	var decryptedKey [utils.AESCTRKeyLength]byte
	var encData ssssEncryptedData

	// retrieve and parse the account data for this key type from SSSS
	err := mach.Client.GetAccountData(string(keyName), &encData)
	if err != nil {
		return decryptedKey, err
	}

	keyEncData, ok := encData.Encrypted[keyID]
	if !ok {
		return decryptedKey, ErrKeyNotFound
	}

	var ivBytes [utils.AESCTRIVLength]byte
	decodedIV, _ := base64.StdEncoding.DecodeString(keyEncData.IV)
	copy(ivBytes[:], decodedIV)

	ciphertextBytes, err := base64.StdEncoding.DecodeString(keyEncData.Ciphertext)
	if err != nil {
		return decryptedKey, err
	}

	// derive the AES and HMAC keys for the requested cross-signing key type using the SSSS key
	aesKey, hmacKey := utils.DeriveKeysSHA256(ssssKey, string(keyName))

	// compare the stored MAC with the one we calculated from the ciphertext
	calcMac := utils.HMACSHA256B64(ciphertextBytes, hmacKey)
	if strings.ReplaceAll(keyEncData.MAC, "=", "") != strings.ReplaceAll(calcMac, "=", "") {
		return decryptedKey, ErrKeyDataMACMismatch
	}

	// use the derived AES key to decrypt the requested cross-signing key seed
	decrypted := utils.XorA256CTR(ciphertextBytes, aesKey, ivBytes)
	decryptedDecoded, err := base64.StdEncoding.DecodeString(string(decrypted))
	if err != nil {
		return decryptedKey, err
	}
	copy(decryptedKey[:], decryptedDecoded)

	return decryptedKey, nil
}

// retrieveSSSSKeyData retrieves the data for the requested key from SSSS.
func (mach *OlmMachine) retrieveSSSSKeyData(keyID string) (*ssssKeyData, error) {
	var keyData ssssKeyData
	err := mach.Client.GetAccountData("m.secret_storage.key."+keyID, &keyData)
	return &keyData, err
}

// verifySSSSKey verifies the SSSS key is valid by calculating and comparing its MAC.
func verifySSSSKey(ssssKey []byte, iv, mac string) error {
	aesKey, hmacKey := utils.DeriveKeysSHA256(ssssKey, "")

	var ivBytes [utils.AESCTRIVLength]byte
	decodedIV, _ := base64.StdEncoding.DecodeString(iv)
	copy(ivBytes[:], decodedIV)

	var zeroBytes [utils.AESCTRKeyLength]byte
	cipher := utils.XorA256CTR(zeroBytes[:], aesKey, ivBytes)

	calcMac := utils.HMACSHA256B64(cipher, hmacKey)

	if strings.ReplaceAll(mac, "=", "") != strings.ReplaceAll(calcMac, "=", "") {
		return ErrStorageKeyMACMismatch
	}

	return nil
}

type CrossSigningSeeds struct {
	MasterKey      []byte
	SelfSigningKey []byte
	UserSigningKey []byte
}

func (mach *OlmMachine) ExportCrossSigningKeys() CrossSigningSeeds {
	return CrossSigningSeeds{
		MasterKey:      mach.crossSigningKeys.MasterKey.Seed,
		SelfSigningKey: mach.crossSigningKeys.SelfSigningKey.Seed,
		UserSigningKey: mach.crossSigningKeys.UserSigningKey.Seed,
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

	mach.crossSigningKeys = &keysCache
	return
}

// keysCacheFromSSSSKey retrieves all the cross-signing keys from SSSS using the given SSSS key and stores them in the olm machine.
func (mach *OlmMachine) keysCacheFromSSSSKey(keyID string, ssssKey []byte) error {
	masterKey, err := mach.retrieveDecryptXSigningKey(AccountDataMasterKeyType, keyID, ssssKey)
	if err != nil {
		return err
	}
	selfSignKey, err := mach.retrieveDecryptXSigningKey(AccountDataSelfSigningKeyType, keyID, ssssKey)
	if err != nil {
		return err
	}
	userSignKey, err := mach.retrieveDecryptXSigningKey(AccountDataUserSigningKeyType, keyID, ssssKey)
	if err != nil {
		return err
	}

	return mach.ImportCrossSigningKeys(CrossSigningSeeds{
		MasterKey:      masterKey[:],
		SelfSigningKey: selfSignKey[:],
		UserSigningKey: userSignKey[:],
	})
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
		return ErrNoPassphrase
	}

	if keyData.Passphrase.Algorithm != SSSSAlgorithmPBKDF2 {
		return fmt.Errorf("%w: %s", ErrUnsupportedPassphraseAlgorithm, keyData.Passphrase.Algorithm)
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

	return mach.keysCacheFromSSSSKey(keyID, ssssKey)
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
	if ssssKey == nil {
		return errors.New("Error decoding recovery key")
	}

	if err := verifySSSSKey(ssssKey, keyData.IV, keyData.MAC); err != nil {
		return err
	}

	mach.Log.Debug("Retrieved and verified SSSS key from recovery key")

	return mach.keysCacheFromSSSSKey(keyID, ssssKey)
}

// GenerateAndUploadCrossSigningKeys generates a new key with all corresponding cross-signing keys.
//
// A passphrase can be provided to generate the SSSS key. If the passphrase is empty, a random key
// is used. The base58-formatted recovery key is the first return parameter.
//
// The account password of the user is required for uploading keys to the server.
func (mach *OlmMachine) GenerateAndUploadCrossSigningKeys(userPassword string, passphrase string) (string, error) {
	var ssssKey []byte
	newKeyData := ssssKeyData{Algorithm: SSSSAlgorithmAESHMACSHA2}

	if len(passphrase) > 0 {
		// if a passphrase is given use it to generate an SSSS key and save the parameters used for PBKDF2
		var saltBytes [24]byte
		if _, err := rand.Read(saltBytes[:]); err != nil {
			panic(err)
		}
		passData := ssssPassphraseData{
			Algorithm:  SSSSAlgorithmPBKDF2,
			Iterations: 500000,
			Bits:       256,
			Salt:       base64.StdEncoding.EncodeToString(saltBytes[:]),
		}
		newKeyData.Passphrase = &passData

		mach.Log.Debug("Generating SSSS key from passphrase")
		ssssKey = utils.PBKDF2SHA512([]byte(passphrase), []byte(passData.Salt), passData.Iterations, passData.Bits)
	} else {
		// if no passphrase generate a random SSSS key
		mach.Log.Debug("Generating random SSSS key")
		ssssKey = make([]byte, 32)
		if _, err := rand.Read(ssssKey); err != nil {
			panic(err)
		}
	}

	var ivBytes [utils.AESCTRIVLength]byte
	if _, err := rand.Read(ivBytes[:]); err != nil {
		panic(err)
	}

	// derive the AES and HMAC key for generating the SSSS key's MAC to be uploaded
	aesKey, hmacKey := utils.DeriveKeysSHA256(ssssKey, "")

	var zeroBytes [utils.AESCTRKeyLength]byte
	cipher := utils.XorA256CTR(zeroBytes[:], aesKey, ivBytes)

	newKeyData.MAC = utils.HMACSHA256B64(cipher, hmacKey)
	newKeyData.IV = base64.StdEncoding.EncodeToString(ivBytes[:])
	mach.Log.Debug("Calculated MAC for AES key: `%v`", newKeyData.MAC)

	// generate the three cross-signing keys
	var keysCache CrossSigningKeysCache
	var err error
	if keysCache.MasterKey, err = olm.NewPkSigning(); err != nil {
		return "", err
	}
	if keysCache.SelfSigningKey, err = olm.NewPkSigning(); err != nil {
		return "", err
	}
	if keysCache.UserSigningKey, err = olm.NewPkSigning(); err != nil {
		return "", err
	}
	mach.Log.Debug("Generated cross-signing keys: Master: `%v` Self-signing: `%v` User-signing: `%v`",
		keysCache.MasterKey.PublicKey, keysCache.SelfSigningKey.PublicKey, keysCache.UserSigningKey.PublicKey)

	err = mach.uploadCrossSigningKeysToServer(&keysCache, userPassword)
	if err != nil {
		return "", fmt.Errorf("failed to upload cross-signing keys: %w", err)
	}

	// generate a key ID for this SSSS key and store the SSSS key info
	var genKeyIDBytes [24]byte
	if _, err := rand.Read(genKeyIDBytes[:]); err != nil {
		panic(err)
	}
	genKeyID := base64.StdEncoding.EncodeToString(genKeyIDBytes[:])
	mach.Log.Debug("Generated SSSS key ID: `%v`", genKeyID)
	if err := mach.Client.SetAccountData("m.secret_storage.key."+genKeyID, newKeyData); err != nil {
		return "", err
	}

	// upload the three cross-signing keys
	if err := mach.uploadCrossSigningKeysToSSSS(genKeyID, ssssKey, &keysCache, true); err != nil {
		return "", err
	}

	// save cross-signing keys, generate and return recovery key
	mach.crossSigningKeys = &keysCache
	return utils.EncodeBase58RecoveryKey(ssssKey), nil
}

// uploadCrossSigningKeysToSSSS stores the given cross-signing keys to SSSS under the given key ID,
// optionally setting the key as the default one.
func (mach *OlmMachine) uploadCrossSigningKeysToSSSS(keyID string, ssssKey []byte, keys *CrossSigningKeysCache, setDefaultKey bool) error {
	if setDefaultKey {
		mach.Client.SetAccountData(string(AccountDataDefaultKeyType), map[string]interface{}{"key": keyID})
	}
	if err := mach.uploadCrossSigningSingleKey(keyID, AccountDataMasterKeyType, keys.MasterKey, ssssKey); err != nil {
		return err
	}
	if err := mach.uploadCrossSigningSingleKey(keyID, AccountDataSelfSigningKeyType, keys.SelfSigningKey, ssssKey); err != nil {
		return err
	}
	if err := mach.uploadCrossSigningSingleKey(keyID, AccountDataUserSigningKeyType, keys.UserSigningKey, ssssKey); err != nil {
		return err
	}
	return nil
}

// uploadCrossSigningSingleKey encrypts and uploads a single cross-signing key to SSSS using the given key.
func (mach *OlmMachine) uploadCrossSigningSingleKey(keyID string, keyName AccountDataKeyType, pk *olm.PkSigning, ssssKey []byte) error {
	aesKey, hmacKey := utils.DeriveKeysSHA256(ssssKey, string(keyName))

	iv := utils.GenA256CTRIV()
	plaintextEncoded := base64.StdEncoding.EncodeToString(pk.Seed)
	encrypted := utils.XorA256CTR([]byte(plaintextEncoded), aesKey, iv)
	macStr := utils.HMACSHA256B64(encrypted, hmacKey)
	ivStr := base64.StdEncoding.EncodeToString(iv[:])

	mach.Log.Debug("Calculated MAC for key %v with ID `%v`: `%v`", keyName, keyID, macStr)

	encryptedXKeyData := ssssEncryptedData{
		Encrypted: map[string]ssssEncryptedKeyData{
			keyID: {
				Ciphertext: base64.StdEncoding.EncodeToString(encrypted),
				IV:         ivStr,
				MAC:        macStr,
			},
		},
	}

	return mach.Client.SetAccountData(string(keyName), encryptedXKeyData)
}
