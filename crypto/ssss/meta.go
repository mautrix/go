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

	"github.com/element-hq/mautrix-go/crypto/utils"
)

// KeyMetadata represents server-side metadata about a SSSS key. The metadata can be used to get
// the actual SSSS key from a passphrase or recovery key.
type KeyMetadata struct {
	id string

	Name      string    `json:"name"`
	Algorithm Algorithm `json:"algorithm"`

	// Note: as per https://spec.matrix.org/v1.9/client-server-api/#msecret_storagev1aes-hmac-sha2,
	// these fields are "maybe padded" base64, so both unpadded and padded values must be supported.
	IV  string `json:"iv"`
	MAC string `json:"mac"`

	Passphrase *PassphraseMetadata `json:"passphrase,omitempty"`
}

// VerifyRecoveryKey verifies that the given passphrase is valid and returns the computed SSSS key.
func (kd *KeyMetadata) VerifyPassphrase(passphrase string) (*Key, error) {
	ssssKey, err := kd.Passphrase.GetKey(passphrase)
	if err != nil {
		return nil, err
	} else if !kd.VerifyKey(ssssKey) {
		return nil, ErrIncorrectSSSSKey
	}

	return &Key{
		ID:       kd.id,
		Key:      ssssKey,
		Metadata: kd,
	}, nil
}

// VerifyRecoveryKey verifies that the given recovery key is valid and returns the decoded SSSS key.
func (kd *KeyMetadata) VerifyRecoveryKey(recoverKey string) (*Key, error) {
	ssssKey := utils.DecodeBase58RecoveryKey(recoverKey)
	if ssssKey == nil {
		return nil, ErrInvalidRecoveryKey
	} else if !kd.VerifyKey(ssssKey) {
		return nil, ErrIncorrectSSSSKey
	}

	return &Key{
		ID:       kd.id,
		Key:      ssssKey,
		Metadata: kd,
	}, nil
}

// VerifyKey verifies the SSSS key is valid by calculating and comparing its MAC.
func (kd *KeyMetadata) VerifyKey(key []byte) bool {
	return strings.TrimRight(kd.MAC, "=") == kd.calculateHash(key)
}

// calculateHash calculates the hash used for checking if the key is entered correctly as described
// in the spec: https://matrix.org/docs/spec/client_server/unstable#m-secret-storage-v1-aes-hmac-sha2
func (kd *KeyMetadata) calculateHash(key []byte) string {
	aesKey, hmacKey := utils.DeriveKeysSHA256(key, "")

	var ivBytes [utils.AESCTRIVLength]byte
	_, _ = base64.RawStdEncoding.Decode(ivBytes[:], []byte(strings.TrimRight(kd.IV, "=")))

	cipher := utils.XorA256CTR(make([]byte, utils.AESCTRKeyLength), aesKey, ivBytes)

	return utils.HMACSHA256B64(cipher, hmacKey)
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
