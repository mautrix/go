// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ssss_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/crypto/ssss"
)

const key1Meta = `
{
  "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
  "passphrase": {
    "algorithm": "m.pbkdf2",
    "iterations": 500000,
    "salt": "y863BOoqOadgDp8S3FtHXikDJEalsQ7d"
  },
  "iv": "xxkTK0L4UzxgAFkQ6XPwsw",
  "mac": "MEhooO0ZhFJNxUhvRMSxBnJfL20wkLgle3ocY0ee/eA"
}
`
const key1ID = "gEJqbfSEMnP5JXXcukpXEX1l0aI3MDs0"

const key1RecoveryKey = "EsTE s92N EtaX s2h6 VQYF 9Kao tHYL mkyL GKMh isZb KJ4E tvoC"
const key1Passphrase = "correct horse battery staple"

const key2Meta = `
{
  "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
  "iv": "O0BOvTqiIAYjC+RMcyHfWw==",
  "mac": "7k6OruQlWg0UmQjxGZ0ad4Q6DdwkgnoI7G6X3IjBYtI="
}
`

const key2MetaBrokenIV = `
{
  "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
  "iv": "O0BOvTqiIAYjC+RMcyHfWwMeowMeowMeow",
  "mac": "7k6OruQlWg0UmQjxGZ0ad4Q6DdwkgnoI7G6X3IjBYtI="
}
`

const key2MetaBrokenMAC = `
{
  "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
  "iv": "O0BOvTqiIAYjC+RMcyHfWw==",
  "mac": "7k6OruQlWg0UmQjxGZ0ad4Q6DdwkgnoI7G6X3IjBYtIMeowMeowMeow"
}
`

const key2ID = "NVe5vK6lZS9gEMQLJw0yqkzmE5Mr7dLv"
const key2RecoveryKey = "EsUC xSxt XJgQ dz19 8WBZ rHdE GZo7 ybsn EFmG Y5HY MDAG GNWe"

func getKeyMeta(meta string) *ssss.KeyMetadata {
	var km ssss.KeyMetadata
	err := json.Unmarshal([]byte(meta), &km)
	if err != nil {
		panic(err)
	}
	return &km
}

func getKey1() *ssss.Key {
	return exerrors.Must(getKeyMeta(key1Meta).VerifyRecoveryKey(key1ID, key1RecoveryKey))
}

func getKey2() *ssss.Key {
	return exerrors.Must(getKeyMeta(key2Meta).VerifyRecoveryKey(key2ID, key2RecoveryKey))
}

func TestKeyMetadata_VerifyRecoveryKey_Correct(t *testing.T) {
	km := getKeyMeta(key1Meta)
	key, err := km.VerifyRecoveryKey(key1ID, key1RecoveryKey)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, key1RecoveryKey, key.RecoveryKey())
}

func TestKeyMetadata_VerifyRecoveryKey_Correct2(t *testing.T) {
	km := getKeyMeta(key2Meta)
	key, err := km.VerifyRecoveryKey(key2ID, key2RecoveryKey)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, key2RecoveryKey, key.RecoveryKey())
}

func TestKeyMetadata_VerifyRecoveryKey_Invalid(t *testing.T) {
	km := getKeyMeta(key1Meta)
	key, err := km.VerifyRecoveryKey(key1ID, "foo")
	assert.True(t, errors.Is(err, ssss.ErrInvalidRecoveryKey), "unexpected error: %v", err)
	assert.Nil(t, key)
}

func TestKeyMetadata_VerifyRecoveryKey_Incorrect(t *testing.T) {
	km := getKeyMeta(key1Meta)
	key, err := km.VerifyRecoveryKey(key2ID, key2RecoveryKey)
	assert.True(t, errors.Is(err, ssss.ErrIncorrectSSSSKey), "unexpected error: %v", err)
	assert.Nil(t, key)
}

func TestKeyMetadata_VerifyPassphrase_Correct(t *testing.T) {
	km := getKeyMeta(key1Meta)
	key, err := km.VerifyPassphrase(key1ID, key1Passphrase)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, key1RecoveryKey, key.RecoveryKey())
}

func TestKeyMetadata_VerifyPassphrase_Incorrect(t *testing.T) {
	km := getKeyMeta(key1Meta)
	key, err := km.VerifyPassphrase(key1ID, "incorrect horse battery staple")
	assert.True(t, errors.Is(err, ssss.ErrIncorrectSSSSKey), "unexpected error %v", err)
	assert.Nil(t, key)
}

func TestKeyMetadata_VerifyPassphrase_NotSet(t *testing.T) {
	km := getKeyMeta(key2Meta)
	key, err := km.VerifyPassphrase(key2ID, "hmm")
	assert.True(t, errors.Is(err, ssss.ErrNoPassphrase), "unexpected error %v", err)
	assert.Nil(t, key)
}

func TestKeyMetadata_VerifyRecoveryKey_CorruptedIV(t *testing.T) {
	km := getKeyMeta(key2MetaBrokenIV)
	key, err := km.VerifyRecoveryKey(key2ID, key2RecoveryKey)
	assert.True(t, errors.Is(err, ssss.ErrCorruptedKeyMetadata), "unexpected error %v", err)
	assert.Nil(t, key)
}

func TestKeyMetadata_VerifyRecoveryKey_CorruptedMAC(t *testing.T) {
	km := getKeyMeta(key2MetaBrokenMAC)
	key, err := km.VerifyRecoveryKey(key2ID, key2RecoveryKey)
	assert.True(t, errors.Is(err, ssss.ErrCorruptedKeyMetadata), "unexpected error %v", err)
	assert.Nil(t, key)
}
