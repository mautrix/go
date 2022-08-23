// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package util_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/util"
)

func TestRandomString_Length(t *testing.T) {
	for i := 0; i < 256; i++ {
		assert.Len(t, util.RandomString(i), i)
	}
}

func TestRandomToken(t *testing.T) {
	for i := 0; i < 256; i++ {
		// Format: prefix_random_checksum
		// Length: prefix (4) + 1 + random (i) + 1 + checksum (6)
		assert.Len(t, util.RandomToken("meow", i), i+5+7)
	}
}
