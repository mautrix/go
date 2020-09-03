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

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/utils"
)

var (
	ErrNoDefaultKeyID                 = errors.New("could not find default key ID")
	ErrNoDefaultKeyAccountDataEvent   = fmt.Errorf("%w: no %s event in account data", ErrNoDefaultKeyID, AccountDataDefaultKeyType)
	ErrNoKeyFieldInAccountDataEvent   = fmt.Errorf("%w: missing key field in account data event", ErrNoDefaultKeyID)
	ErrKeyNotFound                    = errors.New("encrypted data for given key ID not found")
	ErrKeyDataMACMismatch             = errors.New("key data MAC mismatch")
	ErrNoPassphrase                   = errors.New("no passphrase data has been set for the default key")
	ErrUnsupportedPassphraseAlgorithm = errors.New("unsupported passphrase KDF algorithm")
	ErrIncorrectRecoveryKey           = errors.New("incorrect recovery key")
	ErrInvalidRecoveryKey             = errors.New("invalid recovery key")
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

type SSSSPassphraseData struct {
	Algorithm  SSSSAlgorithm `json:"algorithm"`
	Iterations int           `json:"iterations"`
	Salt       string        `json:"salt"`
	Bits       int           `json:"bits"`
}

// GetKey gets the SSSS key from the passphrase.
func (spd *SSSSPassphraseData) GetKey(passphrase string) ([]byte, error) {
	if spd == nil {
		return nil, ErrNoPassphrase
	}

	if spd.Algorithm != SSSSAlgorithmPBKDF2 {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPassphraseAlgorithm, spd.Algorithm)
	}

	bits := 256
	if spd.Bits != 0 {
		bits = spd.Bits
	}

	return utils.PBKDF2SHA512([]byte(passphrase), []byte(spd.Salt), spd.Iterations, bits), nil
}

type SSSSKeyData struct {
	Algorithm  SSSSAlgorithm       `json:"algorithm"`
	IV         string              `json:"iv"`
	MAC        string              `json:"mac"`
	Passphrase *SSSSPassphraseData `json:"passphrase,omitempty"`
}

// VerifyKey verifies the SSSS key is valid by calculating and comparing its MAC.
func (skd *SSSSKeyData) VerifyKey(key []byte) error {
	aesKey, hmacKey := utils.DeriveKeysSHA256(key, "")

	var ivBytes [utils.AESCTRIVLength]byte
	_, _ = base64.StdEncoding.Decode(ivBytes[:], []byte(skd.IV))

	var zeroBytes [utils.AESCTRKeyLength]byte
	cipher := utils.XorA256CTR(zeroBytes[:], aesKey, ivBytes)

	calcMac := utils.HMACSHA256B64(cipher, hmacKey)

	if strings.ReplaceAll(skd.MAC, "=", "") != strings.ReplaceAll(calcMac, "=", "") {
		return ErrIncorrectRecoveryKey
	}

	return nil
}

type SSSSEncryptedKeyData struct {
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv"`
	MAC        string `json:"mac"`
}

type SSSSEncryptedData struct {
	Encrypted map[string]SSSSEncryptedKeyData `json:"encrypted"`
}

// GetDefaultSSSSKeyID retrieves the default key ID for this account from SSSS.
func (mach *OlmMachine) GetDefaultSSSSKeyID() (string, error) {
	var data map[string]string
	err := mach.Client.GetAccountData(string(AccountDataDefaultKeyType), &data)
	if err != nil {
		if httpErr, ok := err.(mautrix.HTTPError); ok && httpErr.RespError != nil && httpErr.RespError.ErrCode == "M_NOT_FOUND" {
			return "", ErrNoDefaultKeyAccountDataEvent
		}
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
	var encData SSSSEncryptedData

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

// RetrieveSSSSKeyData retrieves the data for the requested key from SSSS.
func (mach *OlmMachine) RetrieveSSSSKeyData(keyID string) (keyData *SSSSKeyData, err error) {
	keyData = &SSSSKeyData{}
	err = mach.Client.GetAccountData(fmt.Sprintf("m.secret_storage.key.%s", keyID), keyData)
	return
}

func (mach *OlmMachine) RetrieveDefaultSSSSKeyData() (string, *SSSSKeyData, error) {
	keyID, err := mach.GetDefaultSSSSKeyID()
	if err != nil {
		return "", nil, err
	}
	keyData, err := mach.RetrieveSSSSKeyData(keyID)
	return keyID, keyData, err
}

type CrossSigningSeeds struct {
	MasterKey      []byte
	SelfSigningKey []byte
	UserSigningKey []byte
}

func (mach *OlmMachine) GetCachedCrossSigningKeys() *CrossSigningKeysCache {
	return mach.crossSigningKeys
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
func (mach *OlmMachine) RetrieveCrossSigningKeys(keyID string, ssssKey []byte) error {
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
	keyID, keyData, err := mach.RetrieveDefaultSSSSKeyData()
	if err != nil {
		return err
	}

	ssssKey, err := keyData.Passphrase.GetKey(passphrase)
	if err != nil {
		return err
	}

	if err := keyData.VerifyKey(ssssKey); err != nil {
		return err
	}

	mach.Log.Debug("Retrieved and verified SSSS key from passphrase")

	return mach.RetrieveCrossSigningKeys(keyID, ssssKey)
}

// RetrieveCrossSigningKeysWithRecoveryKey retrieves the cross-signing keys from SSSS using the given recovery key to decrypt them.
func (mach *OlmMachine) RetrieveCrossSigningKeysWithRecoveryKey(recoveryKey string) error {
	keyID, keyData, err := mach.RetrieveDefaultSSSSKeyData()
	if err != nil {
		return err
	}

	ssssKey := utils.DecodeBase58RecoveryKey(recoveryKey)
	if ssssKey == nil {
		return ErrInvalidRecoveryKey
	}

	if err := keyData.VerifyKey(ssssKey); err != nil {
		return err
	}

	mach.Log.Debug("Retrieved and verified SSSS key from recovery key")

	return mach.RetrieveCrossSigningKeys(keyID, ssssKey)
}

// GenerateAndUploadCrossSigningKeys generates a new key with all corresponding cross-signing keys.
//
// A passphrase can be provided to generate the SSSS key. If the passphrase is empty, a random key
// is used. The base58-formatted recovery key is the first return parameter.
//
// The account password of the user is required for uploading keys to the server.
func (mach *OlmMachine) GenerateAndUploadCrossSigningKeys(userPassword, passphrase string) (string, error) {
	var ssssKey []byte
	newKeyData := SSSSKeyData{Algorithm: SSSSAlgorithmAESHMACSHA2}

	if len(passphrase) > 0 {
		// if a passphrase is given use it to generate an SSSS key and save the parameters used for PBKDF2
		var saltBytes [24]byte
		if _, err := rand.Read(saltBytes[:]); err != nil {
			panic(err)
		}
		newKeyData.Passphrase = &SSSSPassphraseData{
			Algorithm:  SSSSAlgorithmPBKDF2,
			Iterations: 500000,
			Bits:       256,
			Salt:       base64.StdEncoding.EncodeToString(saltBytes[:]),
		}

		mach.Log.Debug("Generating SSSS key from passphrase")
		var err error
		ssssKey, err = newKeyData.Passphrase.GetKey(passphrase)
		if err != nil {
			panic(err)
		}
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

	encryptedXKeyData := SSSSEncryptedData{
		Encrypted: map[string]SSSSEncryptedKeyData{
			keyID: {
				Ciphertext: base64.StdEncoding.EncodeToString(encrypted),
				IV:         ivStr,
				MAC:        macStr,
			},
		},
	}

	return mach.Client.SetAccountData(string(keyName), encryptedXKeyData)
}
