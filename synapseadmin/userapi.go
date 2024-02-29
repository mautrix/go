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

	"go.mau.fi/util/jsontime"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/id"
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
	reqURL := cli.BuildAdminURL("v1", "reset_password", req.UserID)
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:      http.MethodPost,
		URL:         reqURL,
		RequestJSON: &req,
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
	_, err = cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          u,
		ResponseJSON: &resp,
	})
	if err == nil && !resp.Available {
		err = fmt.Errorf(`request returned OK status without "available": true`)
	}
	return
}

type DeviceInfo struct {
	mautrix.RespDeviceInfo
	LastSeenUserAgent string `json:"last_seen_user_agent"`
}

type RespListDevices struct {
	Devices []DeviceInfo `json:"devices"`
	Total   int          `json:"total"`
}

// ListDevices gets information about all the devices of a specific user.
//
// https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#list-all-devices
func (cli *Client) ListDevices(ctx context.Context, userID id.UserID) (resp *RespListDevices, err error) {
	_, err = cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          cli.BuildAdminURL("v2", "users", userID, "devices"),
		ResponseJSON: &resp,
	})
	return
}

type RespUserInfo struct {
	UserID       id.UserID           `json:"name"`
	DisplayName  string              `json:"displayname"`
	AvatarURL    id.ContentURIString `json:"avatar_url"`
	Guest        int                 `json:"is_guest"`
	Admin        bool                `json:"admin"`
	Deactivated  bool                `json:"deactivated"`
	Erased       bool                `json:"erased"`
	ShadowBanned bool                `json:"shadow_banned"`
	CreationTS   jsontime.Unix       `json:"creation_ts"`
	AppserviceID string              `json:"appservice_id"`
	UserType     string              `json:"user_type"`

	// TODO: consent fields, threepids, external IDs
}

// GetUserInfo gets information about a specific user account.
//
// https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#query-user-account
func (cli *Client) GetUserInfo(ctx context.Context, userID id.UserID) (resp *RespUserInfo, err error) {
	_, err = cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          cli.BuildAdminURL("v2", "users", userID),
		ResponseJSON: &resp,
	})
	return
}
