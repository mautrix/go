// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package synapseadmin

import (
	"context"
	"fmt"
	"net/http"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// ReqResetPassword is the request content for Client.ResetPassword.
type ReqResetPassword struct {
	// The user whose password to reset.
	UserID id.UserID `json:"-"`

	// The new password for the user. Required.
	NewPassword string `json:"new_password"`
	// Whether all the user's existing devices should be logged out after the password change.
	LogoutDevices bool `json:"logout_devices"`
}

// ResetPassword changes the password of another user using
//
// https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#reset-password
func (cli *Client) ResetPassword(ctx context.Context, req ReqResetPassword) error {
	reqURL := cli.BuildURL(mautrix.SynapseAdminURLPath{"v1", "reset_password", req.UserID})
	_, err := cli.MakeFullRequest(mautrix.FullRequest{
		Method:      http.MethodPost,
		URL:         reqURL,
		RequestJSON: &req,
		Context:     ctx,
	})
	return err
}

// UsernameAvailable checks if a username is valid and available for registration on the server using the admin API.
//
// The response format is the same as mautrix.Client.RegisterAvailable,
// but it works even if registration is disabled on the server.
//
// https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#check-username-availability
func (cli *Client) UsernameAvailable(ctx context.Context, username string) (resp *mautrix.RespRegisterAvailable, err error) {
	u := cli.BuildURLWithQuery(mautrix.SynapseAdminURLPath{"v1", "username_available"}, map[string]string{"username": username})
	_, err = cli.MakeFullRequest(mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          u,
		ResponseJSON: &resp,
		Context:      ctx,
	})
	if err == nil && !resp.Available {
		err = fmt.Errorf(`request returned OK status without "available": true`)
	}
	return
}
