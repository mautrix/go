// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package aescbc_test

import (
	"crypto/aes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/aescbc"
)

func TestAESCBC(t *testing.T) {
	var ciphertext, plaintext []byte
	var err error

	// The key length can be 32, 24, 16  bytes (OR in bits: 128, 192 or 256)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)
	plaintext = []byte("secret message for testing")
	//increase to next block size
	for len(plaintext)%8 != 0 {
		plaintext = append(plaintext, []byte("-")...)
	}

	ciphertext, err = aescbc.Encrypt(key, iv, plaintext)
	require.NoError(t, err)

	resultPlainText, err := aescbc.Decrypt(key, iv, ciphertext)
	require.NoError(t, err)

	assert.Equal(t, string(resultPlainText), string(plaintext))
}

func TestAESCBCCase1(t *testing.T) {
	expected := []byte{
		0xDC, 0x95, 0xC0, 0x78, 0xA2, 0x40, 0x89, 0x89,
		0xAD, 0x48, 0xA2, 0x14, 0x92, 0x84, 0x20, 0x87,
		0xF3, 0xC0, 0x03, 0xDD, 0xC4, 0xA7, 0xB8, 0xA9,
		0x4B, 0xAE, 0xDF, 0xFC, 0x3D, 0x21, 0x4C, 0x38,
	}
	input := make([]byte, 16)
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	encrypted, err := aescbc.Encrypt(key, iv, input)
	require.NoError(t, err)
	assert.Equal(t, expected, encrypted, "encrypted output does not match expected")

	decrypted, err := aescbc.Decrypt(key, iv, encrypted)
	require.NoError(t, err)
	assert.Equal(t, input, decrypted, "decrypted output does not match input")
}
