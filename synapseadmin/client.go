// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package synapseadmin

import (
	"github.com/element-hq/mautrix-go"
)

// Client is a wrapper for the mautrix.Client struct that includes methods for accessing the Synapse admin API.
//
// https://matrix-org.github.io/synapse/latest/usage/administration/admin_api/index.html
type Client struct {
	*mautrix.Client
}

func (cli *Client) BuildAdminURL(path ...any) string {
	return cli.BuildURL(mautrix.SynapseAdminURLPath(path))
}
