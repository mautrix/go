// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/element-hq/mautrix-go"
)

const sampleVersions = `{
  "versions": [
    "r0.0.1",
    "r0.1.0",
    "r0.2.0",
    "r0.3.0",
    "r0.4.0",
    "r0.5.0",
    "r0.6.0",
    "r0.6.1",
    "v1.1",
    "v1.2"
  ],
  "unstable_features": {
    "org.matrix.label_based_filtering": true,
    "org.matrix.e2e_cross_signing": true,
    "org.matrix.msc2432": true,
    "uk.half-shot.msc2666.mutual_rooms": true,
    "io.element.e2ee_forced.public": false,
    "io.element.e2ee_forced.private": false,
    "io.element.e2ee_forced.trusted_private": false,
    "org.matrix.msc3026.busy_presence": false,
    "org.matrix.msc2285": true,
    "org.matrix.msc2716": false,
    "org.matrix.msc3030": false,
    "org.matrix.msc3440.stable": true,
    "fi.mau.msc2815": false
  }
}`

func TestRespVersions_UnmarshalJSON(t *testing.T) {
	var resp mautrix.RespVersions
	err := json.Unmarshal([]byte(sampleVersions), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.ContainsGreaterOrEqual(mautrix.SpecV11))
	assert.True(t, resp.Contains(mautrix.SpecV12))
	assert.True(t, resp.Contains(mautrix.SpecR061))
	assert.True(t, resp.ContainsGreaterOrEqual(mautrix.MustParseSpecVersion("r0.0.0")))
	assert.True(t, !resp.ContainsGreaterOrEqual(mautrix.MustParseSpecVersion("v123.456")))
}

func TestParseSpecVersion(t *testing.T) {
	assert.Equal(t,
		mautrix.SpecVersion{mautrix.SpecVersionFormatR, 0, 1, 0, "r0.1.0"},
		mautrix.MustParseSpecVersion("r0.1.0"))
	assert.Equal(t,
		mautrix.SpecVersion{mautrix.SpecVersionFormatV, 1, 1, 0, "v1.1"},
		mautrix.MustParseSpecVersion("v1.1"))
	assert.Equal(t,
		mautrix.SpecVersion{mautrix.SpecVersionFormatV, 123, 456, 0, "v123.456"},
		mautrix.MustParseSpecVersion("v123.456"))

	invalidVer, err := mautrix.ParseSpecVersion("not a version")
	assert.Error(t, err)
	assert.Equal(t, mautrix.SpecVersion{Raw: "not a version"}, invalidVer)

	// v syntax doesn't allow patch versions
	invalidVer, err = mautrix.ParseSpecVersion("v1.2.3")
	assert.Error(t, err)
	assert.Equal(t, mautrix.SpecVersion{Raw: "v1.2.3"}, invalidVer)

	invalidVer, err = mautrix.ParseSpecVersion("r0.6")
	assert.Error(t, err)
	assert.Equal(t, mautrix.SpecVersion{Raw: "r0.6"}, invalidVer)
}

func TestSpecVersion_String(t *testing.T) {
	assert.Equal(t, "r0.1.0", (&mautrix.SpecVersion{mautrix.SpecVersionFormatR, 0, 1, 0, ""}).String())
	assert.Equal(t, "v1.2", (&mautrix.SpecVersion{mautrix.SpecVersionFormatV, 1, 2, 0, ""}).String())
	assert.Equal(t, "v567.890", (&mautrix.SpecVersion{mautrix.SpecVersionFormatV, 567, 890, 0, ""}).String())
	assert.Equal(t, "invalid version", (&mautrix.SpecVersion{Raw: "invalid version"}).String())
}

func TestSpecVersion_GreaterThan(t *testing.T) {
	assert.True(t, mautrix.MustParseSpecVersion("r0.1.0").GreaterThan(mautrix.MustParseSpecVersion("r0.0.0")))
	assert.True(t, mautrix.MustParseSpecVersion("r0.6.0").GreaterThan(mautrix.MustParseSpecVersion("r0.1.0")))
	assert.True(t, mautrix.MustParseSpecVersion("r0.6.1").GreaterThan(mautrix.MustParseSpecVersion("r0.1.0")))
	assert.True(t, mautrix.MustParseSpecVersion("v1.1").GreaterThan(mautrix.MustParseSpecVersion("r0.6.1")))
	assert.True(t, mautrix.MustParseSpecVersion("v11.11").GreaterThan(mautrix.MustParseSpecVersion("v1.23")))
	assert.True(t, mautrix.MustParseSpecVersion("v1.123").GreaterThan(mautrix.MustParseSpecVersion("v1.1")))
	assert.True(t, !mautrix.MustParseSpecVersion("v1.23").GreaterThan(mautrix.MustParseSpecVersion("v2.31")))
	assert.True(t, !mautrix.MustParseSpecVersion("r0.6.0").GreaterThan(mautrix.MustParseSpecVersion("r0.6.1")))
	assert.True(t, !mautrix.MustParseSpecVersion("r0.6.0").GreaterThan(mautrix.MustParseSpecVersion("r0.6.0")))
	assert.True(t, !mautrix.MustParseSpecVersion("r0.6.0").LessThan(mautrix.MustParseSpecVersion("r0.6.0")))
}
