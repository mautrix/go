// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/exhttp"

	"maunium.net/go/mautrix/federation"
)

func TestServerKeyResponse_VerifySelfSignature(t *testing.T) {
	cli := federation.NewClient("", nil, nil, exhttp.SensibleClientSettings)
	cli.AllowIP = nil
	ctx := context.Background()
	for _, name := range []string{"matrix.org", "maunium.net", "cd.mau.dev", "uwu.mau.dev"} {
		t.Run(name, func(t *testing.T) {
			resp, err := cli.ServerKeys(ctx, name)
			require.NoError(t, err)
			assert.NoError(t, resp.VerifySelfSignature())
		})
	}
}

func TestServerKeyResponse_FailWithFilter(t *testing.T) {
	cli := federation.NewClient("", nil, nil, exhttp.SensibleClientSettings)
	cli.AllowIP = func(ip net.IP) bool {
		return false
	}
	ctx := context.Background()
	_, err := cli.ServerKeys(ctx, "matrix.org")
	assert.ErrorIs(t, err, federation.ErrIPFiltered)
}
