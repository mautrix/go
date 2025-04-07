// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ssss

import (
	"encoding/base64"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/crypto/utils"
)

// KeyMetadata represents server-side metadata about a SSSS key. The metadata can be used to get
// the actual SSSS key from a passphrase or recovery key.
type KeyMetadata struct {
	Name      string    `json:"name"`
	Algorithm Algorithm `json:"algorithm"`

	// Note: as per https://spec.matrix.org/v1.9/client-server-api/#msecret_storagev1aes-hmac-sha2,
	// these fields are "maybe padded" base64, so both unpadded and padded values must be supported.
	IV  string `json:"iv"`
	MAC string `json:"mac"`

	Passphrase *PassphraseMetadata `json:"passphrase,omitempty"`
}

// VerifyRecoveryKey verifies that the given passphrase is valid and returns the computed SSSS key.
func (kd *KeyMetadata) VerifyPassphrase(keyID, passphrase string) (*Key, error) {
	ssssKey, err := kd.Passphrase.GetKey(passphrase)
	if err != nil {
		return nil, err
	} else if err = kd.verifyKey(ssssKey); err != nil {
		return nil, err
	}

	return &Key{
		ID:       keyID,
		Key:      ssssKey,
		Metadata: kd,
	}, nil
}

// VerifyRecoveryKey verifies that the given recovery key is valid and returns the decoded SSSS key.
func (kd *KeyMetadata) VerifyRecoveryKey(keyID, recoveryKey string) (*Key, error) {
	ssssKey := utils.DecodeBase58RecoveryKey(recoveryKey)
	if ssssKey == nil {
		return nil, ErrInvalidRecoveryKey
	} else if err := kd.verifyKey(ssssKey); err != nil {
		return nil, err
	}

	return &Key{
		ID:       keyID,
		Key:      ssssKey,
		Metadata: kd,
	}, nil
}

func (kd *KeyMetadata) verifyKey(key []byte) error {
	unpaddedMAC := strings.TrimRight(kd.MAC, "=")
	expectedMACLength := base64.RawStdEncoding.EncodedLen(utils.SHAHashLength)
	if len(unpaddedMAC) != expectedMACLength {
		return fmt.Errorf("%w: invalid mac length %d (expected %d)", ErrCorruptedKeyMetadata, len(unpaddedMAC), expectedMACLength)
	}
	hash, err := kd.calculateHash(key)
	if err != nil {
		return err
	}
	if unpaddedMAC != hash {
		return ErrIncorrectSSSSKey
	}
	return nil
}

// VerifyKey verifies the SSSS key is valid by calculating and comparing its MAC.
func (kd *KeyMetadata) VerifyKey(key []byte) bool {
	return kd.verifyKey(key) == nil
}

// calculateHash calculates the hash used for checking if the key is entered correctly as described
// in the spec: https://matrix.org/docs/spec/client_server/unstable#m-secret-storage-v1-aes-hmac-sha2
func (kd *KeyMetadata) calculateHash(key []byte) (string, error) {
	aesKey, hmacKey := utils.DeriveKeysSHA256(key, "")
	unpaddedIV := strings.TrimRight(kd.IV, "=")
	expectedIVLength := base64.RawStdEncoding.EncodedLen(utils.AESCTRIVLength)
	if len(unpaddedIV) != expectedIVLength {
		return "", fmt.Errorf("%w: invalid iv length %d (expected %d)", ErrCorruptedKeyMetadata, len(unpaddedIV), expectedIVLength)
	}

	var ivBytes [utils.AESCTRIVLength]byte
	_, err := base64.RawStdEncoding.Decode(ivBytes[:], []byte(unpaddedIV))
	if err != nil {
		return "", fmt.Errorf("%w: failed to decode iv: %w", ErrCorruptedKeyMetadata, err)
	}

	cipher := utils.XorA256CTR(make([]byte, utils.AESCTRKeyLength), aesKey, ivBytes)

	return utils.HMACSHA256B64(cipher, hmacKey), nil
}

// PassphraseMetadata represents server-side metadata about a SSSS key passphrase.
type PassphraseMetadata struct {
	Algorithm  PassphraseAlgorithm `json:"algorithm"`
	Iterations int                 `json:"iterations"`
	Salt       string              `json:"salt"`
	Bits       int                 `json:"bits"`
}

// GetKey gets the SSSS key from the passphrase.
func (pd *PassphraseMetadata) GetKey(passphrase string) ([]byte, error) {
	if pd == nil {
		return nil, ErrNoPassphrase
	}

	if pd.Algorithm != PassphraseAlgorithmPBKDF2 {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPassphraseAlgorithm, pd.Algorithm)
	}

	bits := 256
	if pd.Bits != 0 {
		bits = pd.Bits
	}

	return utils.PBKDF2SHA512([]byte(passphrase), []byte(pd.Salt), pd.Iterations, bits), nil
}
