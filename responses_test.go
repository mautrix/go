// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/crypto/canonicaljson"
)

const sampleData = `{
  "capabilities": {
    "m.room_versions": {
      "default": "9",
      "available": {
        "1": "stable",
        "2": "stable",
        "3": "stable",
        "4": "stable",
        "5": "stable",
        "6": "stable",
        "org.matrix.msc2176": "unstable",
        "7": "stable",
        "8": "stable",
        "9": "stable",
        "org.matrix.msc2716v3": "unstable",
        "org.matrix.msc3787": "unstable",
        "10": "stable"
      }
    },
    "m.change_password": {
      "enabled": true
    },
    "m.set_displayname": {
      "enabled": true
    },
    "m.3pid_changes": {
      "enabled": false
    },
    "fi.mau.custom_field": {
      "🐈️": true
    }
  }
}`

var sampleObject = mautrix.RespCapabilities{
	RoomVersions: &mautrix.CapRoomVersions{
		Default: "9",
		Available: map[string]mautrix.CapRoomVersionStability{
			"1":                    "stable",
			"2":                    "stable",
			"3":                    "stable",
			"4":                    "stable",
			"5":                    "stable",
			"6":                    "stable",
			"org.matrix.msc2176":   "unstable",
			"7":                    "stable",
			"8":                    "stable",
			"9":                    "stable",
			"org.matrix.msc2716v3": "unstable",
			"org.matrix.msc3787":   "unstable",
			"10":                   "stable",
		},
	},
	ChangePassword:  &mautrix.CapBooleanTrue{Enabled: true},
	SetDisplayname:  &mautrix.CapBooleanTrue{Enabled: true},
	ThreePIDChanges: &mautrix.CapBooleanTrue{Enabled: false},
	Custom: map[string]interface{}{
		"fi.mau.custom_field": map[string]interface{}{
			"🐈️": true,
		},
	},
}

func TestRespCapabilities_UnmarshalJSON(t *testing.T) {
	var caps mautrix.RespCapabilities
	err := json.Unmarshal([]byte(sampleData), &caps)
	require.NoError(t, err)
	fmt.Println(caps)

	require.NotNil(t, caps.RoomVersions)
	assert.Equal(t, "9", caps.RoomVersions.Default)
	assert.True(t, caps.RoomVersions.IsStable("10"))

	// Omitted capabilities still support IsEnabled(), and this one defaults to true
	assert.Nil(t, caps.SetAvatarURL)
	assert.True(t, caps.SetAvatarURL.IsEnabled())

	assert.True(t, caps.SetDisplayname.IsEnabled())
	assert.False(t, caps.ThreePIDChanges.IsEnabled())

	assert.Contains(t, caps.Custom, "fi.mau.custom_field")
	assert.NotContains(t, caps.Custom, "m.room_versions")
}

func TestRespCapabilities_MarshalJSON(t *testing.T) {
	data, err := json.Marshal(&sampleObject)
	require.NoError(t, err)
	marshaledString := string(canonicaljson.CanonicalJSONAssumeValid(data))
	origString := string(canonicaljson.CanonicalJSONAssumeValid([]byte(sampleData)))
	assert.Equal(t, marshaledString, origString)
	assert.Len(t, sampleObject.Custom, 1)
}
