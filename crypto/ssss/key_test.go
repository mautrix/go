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

	"github.com/element-hq/mautrix-go/crypto/ssss"
	"github.com/element-hq/mautrix-go/event"
)

const key1CrossSigningMasterKey = `
{
  "encrypted": {
    "gEJqbfSEMnP5JXXcukpXEX1l0aI3MDs0": {
      "iv": "BpKP9nQJTE9jrsAssoxPqQ==",
      "ciphertext": "fNRiiiidezjerTgV+G6pUtmeF3izzj5re/mVvY0hO2kM6kYGrxLuIu2ej80=",
      "mac": "/gWGDGMyOLmbJp+aoSLh5JxCs0AdS6nAhjzpe+9G2Q0="
    }
  }
}
`

var key1CrossSigningMasterKeyDecrypted = []byte{
	0x68, 0xf9, 0x7f, 0xd1, 0x92, 0x2e, 0xec, 0xf6,
	0xb8, 0x2b, 0xb8, 0x90, 0xd2, 0x4d, 0x06, 0x52,
	0x98, 0x4e, 0x7a, 0x1d, 0x70, 0x3b, 0x9e, 0x86,
	0x7b, 0x7e, 0xba, 0xf7, 0xfe, 0xb9, 0x5b, 0x6f,
}

func getEncryptedMasterKey() *ssss.EncryptedAccountDataEventContent {
	var eadec ssss.EncryptedAccountDataEventContent
	err := json.Unmarshal([]byte(key1CrossSigningMasterKey), &eadec)
	if err != nil {
		panic(err)
	}
	return &eadec
}

func TestKey_Decrypt_Success(t *testing.T) {
	key := getKey1()
	emk := getEncryptedMasterKey()
	decrypted, err := emk.Decrypt(event.AccountDataCrossSigningMaster.Type, key)
	assert.NoError(t, err)
	assert.Equal(t, key1CrossSigningMasterKeyDecrypted, decrypted)
}

func TestKey_Decrypt_WrongKey(t *testing.T) {
	key := getKey2()
	emk := getEncryptedMasterKey()
	decrypted, err := emk.Decrypt(event.AccountDataCrossSigningMaster.Type, key)
	assert.True(t, errors.Is(err, ssss.ErrNotEncryptedForKey), "unexpected error %v", err)
	assert.Nil(t, decrypted)
}

func TestKey_Decrypt_FakeKey(t *testing.T) {
	key := getKey2()
	key.ID = key1ID
	emk := getEncryptedMasterKey()
	decrypted, err := emk.Decrypt(event.AccountDataCrossSigningMaster.Type, key)
	assert.True(t, errors.Is(err, ssss.ErrKeyDataMACMismatch), "unexpected error %v", err)
	assert.Nil(t, decrypted)
}

func TestKey_Decrypt_WrongType(t *testing.T) {
	key := getKey1()
	emk := getEncryptedMasterKey()
	decrypted, err := emk.Decrypt(event.AccountDataCrossSigningSelf.Type, key)
	assert.True(t, errors.Is(err, ssss.ErrKeyDataMACMismatch), "unexpected error %v", err)
	assert.Nil(t, decrypted)
}

func TestKey_Encrypt(t *testing.T) {
	key1 := getKey1()
	var evtType = "net.maunium.data"
	var data = []byte{0xde, 0xad, 0xbe, 0xef}
	encrypted := key1.Encrypt(evtType, data)
	decrypted, err := key1.Decrypt(evtType, encrypted)
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}
