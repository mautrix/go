// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/federation"
)

type serverVersionResp struct {
	Server struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"server"`
}

func TestNewFederationClient(t *testing.T) {
	cli := federation.NewFederationHTTPClient()
	resp, err := cli.Get("matrix-federation://maunium.net/_matrix/federation/v1/version")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var respData serverVersionResp
	err = json.NewDecoder(resp.Body).Decode(&respData)
	require.NoError(t, err)
	require.Equal(t, "Synapse", respData.Server.Name)
}
