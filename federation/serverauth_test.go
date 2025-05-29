// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/federation"
)

func TestServerKeyResponse_VerifySelfSignature(t *testing.T) {
	cli := federation.NewClient("", nil, nil)
	ctx := context.Background()
	for _, name := range []string{"matrix.org", "maunium.net", "continuwuity.org"} {
		t.Run(name, func(t *testing.T) {
			resp, err := cli.ServerKeys(ctx, "matrix.org")
			require.NoError(t, err)
			assert.NoError(t, resp.VerifySelfSignature())
		})
	}
}
