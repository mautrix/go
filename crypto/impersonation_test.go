// Copyright (c) 2026 gchahcg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"
)

func TestImpersonatableDeviceKeys(t *testing.T) {
	mach := newMachine(t, "@bot:example.com")
	ghost := id.UserID("@ghost:example.com")

	dk, err := mach.ImpersonatableDeviceKeys(ghost)
	require.NoError(t, err)

	assert.Equal(t, ghost, dk.UserID)
	assert.Equal(t, mach.Client.DeviceID, dk.DeviceID)

	t.Run("json shape", func(t *testing.T) {
		raw, err := json.Marshal(dk)
		require.NoError(t, err)
		var parsed map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &parsed))
		assert.JSONEq(t, `[]`, string(parsed["algorithms"]))
		assert.JSONEq(t, `{}`, string(parsed["keys"]))
		var imp map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(parsed["fi.mau.msc4350.impersonator"], &imp))
		assert.NotContains(t, imp, "signatures")
	})

	t.Run("signatures", func(t *testing.T) {
		require.Len(t, dk.Signatures, 1)
		botSigs, ok := dk.Signatures[mach.Client.UserID]
		require.True(t, ok)
		require.Len(t, botSigs, 1)
		assert.Contains(t, botSigs, id.NewKeyID(id.KeyAlgorithmEd25519, mach.Client.DeviceID.String()))
	})

	t.Run("verify", func(t *testing.T) {
		key := mach.account.SigningKey()
		keyName := mach.Client.DeviceID.String()
		ok, err := signatures.VerifySignatureJSON(dk, mach.Client.UserID, keyName, key)
		require.NoError(t, err)
		assert.True(t, ok)

		dk.Impersonator.Keys[id.NewDeviceKeyID(id.KeyAlgorithmCurve25519, mach.Client.DeviceID)] = "tampered"
		ok, err = signatures.VerifySignatureJSON(dk, mach.Client.UserID, keyName, key)
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestImpersonatorMatchesOwnDeviceKeys(t *testing.T) {
	mach := newMachine(t, "@bot:example.com")
	dk, err := mach.ImpersonatableDeviceKeys("@ghost:example.com")
	require.NoError(t, err)
	own := mach.account.ownDeviceKeys(mach.Client.UserID, mach.Client.DeviceID)
	assert.Equal(t, own.UserID, dk.Impersonator.UserID)
	assert.Equal(t, own.DeviceID, dk.Impersonator.DeviceID)
	assert.Equal(t, own.Algorithms, dk.Impersonator.Algorithms)
	assert.Equal(t, own.Keys, dk.Impersonator.Keys)
}

func TestGetInitialKeysUnchanged(t *testing.T) {
	mach := newMachine(t, "@bot:example.com")
	dk := mach.account.getInitialKeys("@bot:example.com", "device1")
	assert.Equal(t, []id.Algorithm{id.AlgorithmMegolmV1, id.AlgorithmOlmV1}, dk.Algorithms)
	assert.Nil(t, dk.Impersonator)
	assert.Len(t, dk.Keys, 2)
	ok, err := signatures.VerifySignatureJSON(dk, "@bot:example.com", "device1", mach.account.SigningKey())
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Len(t, dk.Signatures, 1)
}

func TestImpersonatableDeviceKeysNoAccount(t *testing.T) {
	_, err := (&OlmMachine{}).ImpersonatableDeviceKeys("@ghost:example.com")
	assert.ErrorIs(t, err, ErrOlmAccountNotLoaded)
}
