// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/federation"
)

type parseTestCase struct {
	name       string
	serverName string
	hostname   string
	port       uint16
}

func TestParseServerName(t *testing.T) {
	testCases := []parseTestCase{{
		"Domain",
		"matrix.org",
		"matrix.org",
		0,
	}, {
		"Domain with port",
		"matrix.org:8448",
		"matrix.org",
		8448,
	}, {
		"IPv4 literal",
		"1.2.3.4",
		"1.2.3.4",
		0,
	}, {
		"IPv4 literal with port",
		"1.2.3.4:8448",
		"1.2.3.4",
		8448,
	}, {
		"IPv6 literal",
		"[1234:5678::abcd]",
		"1234:5678::abcd",
		0,
	}, {
		"IPv6 literal with port",
		"[1234:5678::abcd]:8448",
		"1234:5678::abcd",
		8448,
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hostname, port, ok := federation.ParseServerName(tc.serverName)
			assert.True(t, ok)
			assert.Equal(t, tc.hostname, hostname)
			assert.Equal(t, tc.port, port)
		})
	}
}
