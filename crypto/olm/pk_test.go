// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Only run this test if goo is disabled (that is, libolm is used).
//go:build !goolm

package olm_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/goolm/pk"
	"maunium.net/go/mautrix/crypto/olm"
)

func FuzzSign(f *testing.F) {
	seed := []byte("Quohboh3ka3ooghequier9lee8Bahwoh")
	goolmPkSigning, err := pk.NewSigningFromSeed(seed)
	require.NoError(f, err)

	libolmPkSigning, err := olm.NewPKSigningFromSeed(seed)
	require.NoError(f, err)

	f.Add([]byte("message"))

	f.Fuzz(func(t *testing.T, message []byte) {
		// libolm breaks with empty messages, so don't perform differential
		// fuzzing on that.
		if len(message) == 0 {
			return
		}

		libolmResult, libolmErr := libolmPkSigning.Sign(message)
		goolmResult, goolmErr := goolmPkSigning.Sign(message)

		assert.Equal(t, goolmErr, libolmErr)
		assert.Equal(t, goolmResult, libolmResult)
	})
}

// func FuzzDecrypt(f *testing.F) {
// 	f.Add([]byte("plaintext"))

// 	f.Fuzz(func(t *testing.T, plaintext []byte) {
// 		keyPair, err := crypto.Curve25519GenerateKey(nil)
// 		require.NoError(t, err)

// 		goolmEncryption, err := pk.NewEncryption(keyPair.B64Encoded())
// 		require.NoError(t, err)

// 		ciphertext, mac, err := goolmEncryption.Encrypt(plaintext, keyPair.PrivateKey)
// 		assert.NoError(t, err)

// 		goolmPkDecryption, err := pk.NewDecryptionFromPrivate(keyPair.PrivateKey)
// 		require.NoError(t, err)

// 		libolmPkDecryption, err := olm.NewPkDecryption(keyPair.PrivateKey)
// 		require.NoError(t, err)

// 		fmt.Printf("mac=%s\n", mac)
// 		fmt.Printf("ciphertext=%v\n", ciphertext)

// 		libolmResult, libolmErr := libolmPkDecryption.Decrypt([]byte(keyPair.B64Encoded().String()), mac, []byte(base64.RawStdEncoding.EncodeToString(ciphertext)))
// 		goolmResult, goolmErr := goolmPkDecryption.Decrypt(keyPair.B64Encoded(), mac, ciphertext)

// 		assert.Equal(t, libolmErr, goolmErr)
// 		assert.Equal(t, libolmResult, goolmResult)
// 	})
// }
