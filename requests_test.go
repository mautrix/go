// Copyright (c) 2026 gchahcg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// Example from MSC4350 ("Bridge ghost device keys"), using the unstable prefix for the impersonator field.
const ghostDeviceKeysJSON = `{
    "algorithms": [],
    "device_id": "ZVYTEW6WS0",
    "fi.mau.msc4350.impersonator": {
        "algorithms": [
            "m.olm.v1.curve25519-aes-sha2",
            "m.megolm.v1.aes-sha2"
        ],
        "device_id": "JLAFKJWSCS",
        "keys": {
            "curve25519:JLAFKJWSCS": "[bridge-device-curve25519-key]",
            "ed25519:JLAFKJWSCS": "[bridge-device-ed25519-key]"
        },
        "user_id": "@bridgebot:example.com"
    },
    "keys": {},
    "signatures": {
        "@bridgebot:example.com": {
            "ed25519:JLAFKJWSCS": "[signature-from-bridge-device]"
        }
    },
    "user_id": "@bridge_123456:example.com"
}`

func TestDeviceKeys_Impersonator(t *testing.T) {
	var dk mautrix.DeviceKeys
	require.NoError(t, json.Unmarshal([]byte(ghostDeviceKeysJSON), &dk))

	require.NotNil(t, dk.Impersonator)
	assert.Equal(t, id.UserID("@bridgebot:example.com"), dk.Impersonator.UserID)
	assert.Equal(t, id.DeviceID("JLAFKJWSCS"), dk.Impersonator.DeviceID)
	assert.Len(t, dk.Impersonator.Algorithms, 2)
	assert.Len(t, dk.Impersonator.Keys, 2)
	assert.NotContains(t, dk.Extra, "fi.mau.msc4350.impersonator")

	out, err := json.Marshal(&dk)
	require.NoError(t, err)
	assert.JSONEq(t, ghostDeviceKeysJSON, string(out))
}

func TestDeviceKeys_NoImpersonator(t *testing.T) {
	dk := mautrix.DeviceKeys{
		UserID:     "@user:example.com",
		DeviceID:   "DEVICE",
		Algorithms: []id.Algorithm{},
		Keys:       mautrix.KeyMap{},
	}
	out, err := json.Marshal(&dk)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "fi.mau.msc4350.impersonator")
}
