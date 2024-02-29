// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ssss

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/element-hq/mautrix-go/crypto/utils"
)

// Key represents a SSSS private key and related metadata.
type Key struct {
	ID       string       `json:"-"`
	Key      []byte       `json:"-"`
	Metadata *KeyMetadata `json:"-"`
}

// NewKey generates a new SSSS key, optionally based on the given passphrase.
//
// Errors are only returned if crypto/rand runs out of randomness.
func NewKey(passphrase string) (*Key, error) {
	// We don't support any other algorithms currently.
	keyData := KeyMetadata{Algorithm: AlgorithmAESHMACSHA2}

	var ssssKey []byte
	if len(passphrase) > 0 {
		// There's a passphrase. We need to generate a salt for it, set the metadata
		// and then compute the key using the passphrase and the metadata.
		saltBytes := make([]byte, 24)
		if _, err := rand.Read(saltBytes); err != nil {
			return nil, fmt.Errorf("failed to get random bytes for salt: %w", err)
		}
		keyData.Passphrase = &PassphraseMetadata{
			Algorithm:  PassphraseAlgorithmPBKDF2,
			Iterations: 500000,
			Salt:       base64.StdEncoding.EncodeToString(saltBytes),
			Bits:       256,
		}
		var err error
		ssssKey, err = keyData.Passphrase.GetKey(passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to get key from passphrase: %w", err)
		}
	} else {
		// No passphrase, just generate a random key
		ssssKey = make([]byte, 32)
		if _, err := rand.Read(ssssKey); err != nil {
			return nil, fmt.Errorf("failed to get random bytes for key: %w", err)
		}
	}

	// Generate a random ID for the key. It's what identifies the key in account data.
	keyIDBytes := make([]byte, 24)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, fmt.Errorf("failed to get random bytes for key ID: %w", err)
	}

	// We store a certain hash in the key metadata so that clients can check if the user entered the correct key.
	var ivBytes [utils.AESCTRIVLength]byte
	if _, err := rand.Read(ivBytes[:]); err != nil {
		return nil, fmt.Errorf("failed to get random bytes for IV: %w", err)
	}
	keyData.IV = base64.RawStdEncoding.EncodeToString(ivBytes[:])
	keyData.MAC = keyData.calculateHash(ssssKey)

	return &Key{
		Key:      ssssKey,
		ID:       base64.RawStdEncoding.EncodeToString(keyIDBytes),
		Metadata: &keyData,
	}, nil
}

// RecoveryKey gets the recovery key for this SSSS key.
func (key *Key) RecoveryKey() string {
	return utils.EncodeBase58RecoveryKey(key.Key)
}

// Encrypt encrypts the given data with this key.
func (key *Key) Encrypt(eventType string, data []byte) EncryptedKeyData {
	aesKey, hmacKey := utils.DeriveKeysSHA256(key.Key, eventType)

	iv := utils.GenA256CTRIV()
	// For some reason, keys in secret storage are base64 encoded before encrypting.
	// Even more confusingly, it's a part of each key type's spec rather than the secrets spec.
	// Key backup (`m.megolm_backup.v1`): https://spec.matrix.org/v1.9/client-server-api/#recovery-key
	// Cross-signing (master, etc): https://spec.matrix.org/v1.9/client-server-api/#cross-signing (the very last paragraph)
	// It's also not clear whether unpadded base64 is the right option, but assuming it is because everything else is unpadded.
	payload := make([]byte, base64.RawStdEncoding.EncodedLen(len(data)))
	base64.RawStdEncoding.Encode(payload, data)
	utils.XorA256CTR(payload, aesKey, iv)

	return EncryptedKeyData{
		Ciphertext: base64.RawStdEncoding.EncodeToString(payload),
		IV:         base64.RawStdEncoding.EncodeToString(iv[:]),
		MAC:        utils.HMACSHA256B64(payload, hmacKey),
	}
}

// Decrypt decrypts the given encrypted data with this key.
func (key *Key) Decrypt(eventType string, data EncryptedKeyData) ([]byte, error) {
	var ivBytes [utils.AESCTRIVLength]byte
	decodedIV, _ := base64.RawStdEncoding.DecodeString(strings.TrimRight(data.IV, "="))
	copy(ivBytes[:], decodedIV)

	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(data.Ciphertext, "="))
	if err != nil {
		return nil, err
	}

	// derive the AES and HMAC keys for the requested event type using the SSSS key
	aesKey, hmacKey := utils.DeriveKeysSHA256(key.Key, eventType)

	// compare the stored MAC with the one we calculated from the ciphertext
	calcMac := utils.HMACSHA256B64(payload, hmacKey)
	if strings.TrimRight(data.MAC, "=") != calcMac {
		return nil, ErrKeyDataMACMismatch
	}

	utils.XorA256CTR(payload, aesKey, ivBytes)
	decryptedDecoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(string(payload), "="))
	return decryptedDecoded, err
}
