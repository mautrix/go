// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/federation"
)

func TestClient_Version(t *testing.T) {
	cli := federation.NewClient("", nil, nil)
	resp, err := cli.Version(context.TODO(), "maunium.net")
	require.NoError(t, err)
	require.Equal(t, "Synapse", resp.Server.Name)
}
