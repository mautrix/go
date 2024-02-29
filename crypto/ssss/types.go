// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ssss

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/element-hq/mautrix-go/event"
)

var (
	ErrNoDefaultKeyID               = errors.New("could not find default key ID")
	ErrNoDefaultKeyAccountDataEvent = fmt.Errorf("%w: no %s event in account data", ErrNoDefaultKeyID, event.AccountDataSecretStorageDefaultKey.Type)
	ErrNoKeyFieldInAccountDataEvent = fmt.Errorf("%w: missing key field in account data event", ErrNoDefaultKeyID)
	ErrNoKeyGiven                   = errors.New("must provide at least one key to encrypt for")

	ErrNotEncryptedForKey             = errors.New("data is not encrypted for given key ID")
	ErrKeyDataMACMismatch             = errors.New("key data MAC mismatch")
	ErrNoPassphrase                   = errors.New("no passphrase data has been set for the default key")
	ErrUnsupportedPassphraseAlgorithm = errors.New("unsupported passphrase KDF algorithm")
	ErrIncorrectSSSSKey               = errors.New("incorrect SSSS key")
	ErrInvalidRecoveryKey             = errors.New("invalid recovery key")
)

// Algorithm is the identifier for an SSSS encryption algorithm.
type Algorithm string

const (
	// AlgorithmAESHMACSHA2 is the current main algorithm.
	AlgorithmAESHMACSHA2 Algorithm = "m.secret_storage.v1.aes-hmac-sha2"
	// AlgorithmCurve25519AESSHA2 is the old algorithm
	AlgorithmCurve25519AESSHA2 Algorithm = "m.secret_storage.v1.curve25519-aes-sha2"
)

// PassphraseAlgorithm is the identifier for an algorithm used to derive a key from a passphrase for SSSS.
type PassphraseAlgorithm string

const (
	// PassphraseAlgorithmPBKDF2 is the current main algorithm
	PassphraseAlgorithmPBKDF2 PassphraseAlgorithm = "m.pbkdf2"
)

type EncryptedKeyData struct {
	// Note: as per https://spec.matrix.org/v1.9/client-server-api/#msecret_storagev1aes-hmac-sha2-1,
	// these fields are "maybe padded" base64, so both unpadded and padded values must be supported.
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv"`
	MAC        string `json:"mac"`
}

type EncryptedAccountDataEventContent struct {
	Encrypted map[string]EncryptedKeyData `json:"encrypted"`
}

func (ed *EncryptedAccountDataEventContent) Decrypt(eventType string, key *Key) ([]byte, error) {
	keyEncData, ok := ed.Encrypted[key.ID]
	if !ok {
		return nil, ErrNotEncryptedForKey
	}

	return key.Decrypt(eventType, keyEncData)
}

func init() {
	encryptedContent := reflect.TypeOf(&EncryptedAccountDataEventContent{})
	event.TypeMap[event.AccountDataCrossSigningMaster] = encryptedContent
	event.TypeMap[event.AccountDataCrossSigningSelf] = encryptedContent
	event.TypeMap[event.AccountDataCrossSigningUser] = encryptedContent
	event.TypeMap[event.AccountDataSecretStorageDefaultKey] = reflect.TypeOf(&DefaultSecretStorageKeyContent{})
	event.TypeMap[event.AccountDataSecretStorageKey] = reflect.TypeOf(&KeyMetadata{})
	event.TypeMap[event.AccountDataMegolmBackupKey] = reflect.TypeOf(&EncryptedAccountDataEventContent{})
}
