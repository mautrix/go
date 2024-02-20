// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package synapseadmin

import (
	"context"
	"net/http"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
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

func (cli *Client) MessagesAdmin(ctx context.Context, roomID id.RoomID, from, to string) (resp RespMessagesAdmin, err error) {
	req := ReqSyncAdmin{from: from, to: to}
	urlPath := cli.BuildURLWithQuery(mautrix.SynapseAdminURLPath{"v1", "rooms", roomID, "messages"}, req.BuildQuery())
	fullReq := mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          urlPath,
		ResponseJSON: &resp,
		MaxAttempts:  1,
	}
	_, err = cli.MakeFullRequest(ctx, fullReq)
	return resp, err
}

type ReqSyncAdmin struct {
	from string
	to   string
}

func (req *ReqSyncAdmin) BuildQuery() map[string]string {
	query := map[string]string{}
	if req.from != "" {
		query["from"] = req.from
	}
	if req.to != "" {
		query["to"] = req.to
	}
	return query
}
