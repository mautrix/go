// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package util_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/util"
)

func TestRandomString_Length(t *testing.T) {
	for i := 0; i < 256; i++ {
		require.Len(t, util.RandomString(i), i)
	}
}

var randomStringRegex = regexp.MustCompile(`^[0-9A-Za-z]*$`)
var randomTokenRegex = regexp.MustCompile(`^.+?_[0-9A-Za-z]*_[0-9A-Za-z]{6}$`)

func TestRandomString_Content(t *testing.T) {
	for i := 0; i < 256; i++ {
		require.Regexp(t, randomStringRegex, util.RandomString(i))
	}
}

func TestRandomToken(t *testing.T) {
	for i := 0; i < 256; i++ {
		// Format: prefix_random_checksum
		// Length: prefix (4) + 1 + random (i) + 1 + checksum (6)
		token := util.RandomToken("meow", i)
		require.Len(t, token, i+5+7)
		require.Regexp(t, randomTokenRegex, token)
	}
}

func BenchmarkRandomString8(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.RandomString(8)
	}
}

func BenchmarkRandomString32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.RandomString(32)
	}
}

func BenchmarkRandomString50(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.RandomString(50)
	}
}

func BenchmarkRandomString256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.RandomString(256)
	}
}

func BenchmarkRandomToken32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.RandomToken("meow", 32)
	}
}
