// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Only run this test if goolm is disabled (that is, libolm is used).
//go:build !goolm

package olm_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	goolmsession "maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/olm"
)

func TestBlankSession(t *testing.T) {
	libolmSession := olm.NewBlankLibOlmSession()
	goolmSession := goolmsession.NewOlmSession()

	assert.Equal(t, libolmSession.ID(), goolmSession.ID())
	assert.Equal(t, libolmSession.HasReceivedMessage(), goolmSession.HasReceivedMessage())
	assert.Equal(t, libolmSession.EncryptMsgType(), goolmSession.EncryptMsgType())
	assert.Equal(t, libolmSession.Describe(), goolmSession.Describe())

	libolmPickled, err := libolmSession.Pickle([]byte("test"))
	assert.NoError(t, err)
	goolmPickled, err := goolmSession.Pickle([]byte("test"))
	assert.NoError(t, err)
	assert.Equal(t, goolmPickled, libolmPickled)
}

func TestSessionPickle(t *testing.T) {
	pickledDataFromLibOlm := []byte("icDKYm0b4aO23WgUuOxdpPoxC0UlEOYPVeuduNH3IkpFsmnWx5KuEOpxGiZw5IuB/sSn2RZUCTiJ90IvgC7AClkYGHep9O8lpiqQX73XVKD9okZDCAkBc83eEq0DKYC7HBkGRAU/4T6QPIBBY3UK4QZwULLE/fLsi3j4YZBehMtnlsqgHK0q1bvX4cRznZItVKR4ro0O9EAk6LLxJtSnRu5elSUk7YXT")
	pickleKey := []byte("secret_key")

	goolmSession := goolmsession.NewOlmSession()
	err := goolmSession.Unpickle(pickledDataFromLibOlm, pickleKey)
	assert.NoError(t, err)

	libolmSession := olm.NewBlankLibOlmSession()
	err = libolmSession.Unpickle(pickledDataFromLibOlm, pickleKey)
	assert.NoError(t, err)

	// Reset the pickle data since libolmSession.Unpickle modifies it.
	pickledDataFromLibOlm = []byte("icDKYm0b4aO23WgUuOxdpPoxC0UlEOYPVeuduNH3IkpFsmnWx5KuEOpxGiZw5IuB/sSn2RZUCTiJ90IvgC7AClkYGHep9O8lpiqQX73XVKD9okZDCAkBc83eEq0DKYC7HBkGRAU/4T6QPIBBY3UK4QZwULLE/fLsi3j4YZBehMtnlsqgHK0q1bvX4cRznZItVKR4ro0O9EAk6LLxJtSnRu5elSUk7YXT")

	goolmPickled, err := goolmSession.Pickle(pickleKey)
	assert.NoError(t, err)
	assert.Equal(t, pickledDataFromLibOlm, goolmPickled)

	libolmPickled, err := libolmSession.Pickle(pickleKey)
	assert.Equal(t, pickledDataFromLibOlm, libolmPickled)
	assert.NoError(t, err)
}

// func FuzzSession(f *testing.F) {
// 	f.Add([]byte("plaintext"))

// 	identityKeyAlice, err := crypto.Curve25519GenerateKey(nil)
// 	require.NoError(f, err)
// 	identityKeyBob, err := crypto.Curve25519GenerateKey(nil)
// 	require.NoError(f, err)

// 	f.Fuzz(func(t *testing.T, plaintext []byte) {
// 		// identityKeyAlice crypto.Curve25519KeyPair, identityKeyBob crypto.Curve25519PublicKey, oneTimeKeyBob crypto.Curve25519PublicKey

// 		goolmSession, err := goolmsession.NewOutboundOlmSession(identityKeyAlice, identityKeyBob.PublicKey, otk)
// 		assert.NoError(t, err)

// 		libolmAccount := olm.NewAccount()
// 		libolmSession, err := libolmAccount.NewInboundSessionFrom(id.Curve25519(identityKeyBob.PublicKey), string(otk))

// 		goolmMsgType, goolmCiphertext, goolmErr := goolmSession.Encrypt(plaintext)
// 		assert.NoError(t, goolmErr)

// 		libolmMsgType, libolmCiphertext, libolmErr := libolmSession.Encrypt(plaintext)
// 		assert.NoError(t, libolmErr)

// 		assert.Equal(t, goolmMsgType, libolmMsgType)
// 		assert.Equal(t, goolmCiphertext, libolmCiphertext)
// 	})
// }
