// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/federation"
)

type resolveTestCase struct {
	name       string
	serverName string
	expected   federation.ResolvedServerName
}

func TestResolveServerName(t *testing.T) {
	// See https://t2bot.io/docs/resolvematrix/ for more info on the RM test cases
	testCases := []resolveTestCase{{
		"maunium",
		"maunium.net",
		federation.ResolvedServerName{
			HostHeader: "federation.mau.chat",
			IPPort:     []string{"meow.host.mau.fi:443"},
		},
	}, {
		"IP literal",
		"135.181.208.158",
		federation.ResolvedServerName{
			HostHeader: "135.181.208.158",
			IPPort:     []string{"135.181.208.158:8448"},
		},
	}, {
		"IP literal with port",
		"135.181.208.158:8447",
		federation.ResolvedServerName{
			HostHeader: "135.181.208.158:8447",
			IPPort:     []string{"135.181.208.158:8447"},
		},
	}, {
		"RM Step 2",
		"2.s.resolvematrix.dev:7652",
		federation.ResolvedServerName{
			HostHeader: "2.s.resolvematrix.dev:7652",
			IPPort:     []string{"2.s.resolvematrix.dev:7652"},
		},
	}, {
		"RM Step 3B",
		"3b.s.resolvematrix.dev",
		federation.ResolvedServerName{
			HostHeader: "wk.3b.s.resolvematrix.dev:7753",
			IPPort:     []string{"wk.3b.s.resolvematrix.dev:7753"},
		},
	}, {
		"RM Step 3C",
		"3c.s.resolvematrix.dev",
		federation.ResolvedServerName{
			HostHeader: "wk.3c.s.resolvematrix.dev",
			IPPort:     []string{"srv.wk.3c.s.resolvematrix.dev:7754"},
		},
	}, {
		"RM Step 3C MSC4040",
		"3c.msc4040.s.resolvematrix.dev",
		federation.ResolvedServerName{
			HostHeader: "wk.3c.msc4040.s.resolvematrix.dev",
			IPPort:     []string{"srv.wk.3c.msc4040.s.resolvematrix.dev:7053"},
		},
	}, {
		"RM Step 3D",
		"3d.s.resolvematrix.dev",
		federation.ResolvedServerName{
			HostHeader: "wk.3d.s.resolvematrix.dev",
			IPPort:     []string{"wk.3d.s.resolvematrix.dev:8448"},
		},
	}, {
		"RM Step 4",
		"4.s.resolvematrix.dev",
		federation.ResolvedServerName{
			HostHeader: "4.s.resolvematrix.dev",
			IPPort:     []string{"srv.4.s.resolvematrix.dev:7855"},
		},
	}, {
		"RM Step 4 MSC4040",
		"4.msc4040.s.resolvematrix.dev",
		federation.ResolvedServerName{
			HostHeader: "4.msc4040.s.resolvematrix.dev",
			IPPort:     []string{"srv.4.msc4040.s.resolvematrix.dev:7054"},
		},
	}, {
		"RM Step 5",
		"5.s.resolvematrix.dev",
		federation.ResolvedServerName{
			HostHeader: "5.s.resolvematrix.dev",
			IPPort:     []string{"5.s.resolvematrix.dev:8448"},
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.expected.ServerName = tc.serverName
			resp, err := federation.ResolveServerName(context.TODO(), tc.serverName)
			require.NoError(t, err)
			resp.Expires = time.Time{}
			assert.Equal(t, tc.expected, *resp)
		})
	}
}
