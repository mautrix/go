// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package olm_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/crypto/goolm/account"
	"maunium.net/go/mautrix/crypto/libolm"
)

// TestAccount_UnpickleLibolmToGoolm tests creating an account from libolm,
// pickling it, and importing it into goolm.
func TestAccount_UnpickleLibolmToGoolm(t *testing.T) {
	libolmAccount, err := libolm.NewAccount(nil)
	require.NoError(t, err)
	libolmEd25519, libolmCurve25519, err := libolmAccount.IdentityKeys()
	require.NoError(t, err)

	libolmPickled, err := libolmAccount.Pickle([]byte("test"))
	require.NoError(t, err)

	goolmAccount, err := account.AccountFromPickled(libolmPickled, []byte("test"))
	require.NoError(t, err)
	goolmEd25519, goolmCurve25519, err := goolmAccount.IdentityKeys()
	require.NoError(t, err)

	assert.Equal(t, libolmEd25519, goolmEd25519)
	assert.Equal(t, libolmCurve25519, goolmCurve25519)

	goolmPickled, err := goolmAccount.Pickle([]byte("test"))
	require.NoError(t, err)
	assert.Equal(t, libolmPickled, goolmPickled)
}

// TestAccount_UnpickleGoolmToLibolm tests creating an account from goolm,
// pickling it, and importing it into libolm.
func TestAccount_UnpickleGoolmToLibolm(t *testing.T) {
	goolmAccount, err := account.NewAccount(nil)
	require.NoError(t, err)
	goolmEd25519, goolmCurve25519, err := goolmAccount.IdentityKeys()
	require.NoError(t, err)

	goolmPickled, err := goolmAccount.Pickle([]byte("test"))
	require.NoError(t, err)

	libolmAccount, err := libolm.AccountFromPickled(bytes.Clone(goolmPickled), []byte("test"))
	require.NoError(t, err)
	libolmEd25519, libolmCurve25519, err := libolmAccount.IdentityKeys()
	require.NoError(t, err)

	assert.Equal(t, libolmEd25519, goolmEd25519)
	assert.Equal(t, libolmCurve25519, goolmCurve25519)

	libolmPickled, err := libolmAccount.Pickle([]byte("test"))
	require.NoError(t, err)
	assert.Equal(t, goolmPickled, libolmPickled)
}

func FuzzAccount_Sign(f *testing.F) {
	f.Add([]byte("anything"))

	libolmAccount := exerrors.Must(libolm.NewAccount(nil))
	goolmAccount := exerrors.Must(account.AccountFromPickled(exerrors.Must(libolmAccount.Pickle([]byte("test"))), []byte("test")))

	f.Fuzz(func(t *testing.T, message []byte) {
		if len(message) == 0 {
			t.Skip("empty message is not supported")
		}

		libolmSignature, err := libolmAccount.Sign(bytes.Clone(message))
		require.NoError(t, err)
		goolmSignature, err := goolmAccount.Sign(bytes.Clone(message))
		require.NoError(t, err)

		assert.Equal(t, goolmSignature, libolmSignature)
		goolmSignatureBytes, err := base64.RawStdEncoding.DecodeString(string(goolmSignature))
		require.NoError(t, err)
		libolmSignatureBytes, err := base64.RawStdEncoding.DecodeString(string(libolmSignature))
		require.NoError(t, err)

		libolmEd25519, _, err := libolmAccount.IdentityKeys()
		require.NoError(t, err)

		assert.True(t, ed25519.Verify(ed25519.PublicKey(libolmEd25519.Bytes()), message, libolmSignatureBytes))
		assert.True(t, ed25519.Verify(ed25519.PublicKey(libolmEd25519.Bytes()), message, goolmSignatureBytes))

		assert.True(t, goolmAccount.IdKeys.Ed25519.Verify(bytes.Clone(message), libolmSignatureBytes))
		assert.True(t, goolmAccount.IdKeys.Ed25519.Verify(bytes.Clone(message), goolmSignatureBytes))
	})
}
