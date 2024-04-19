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
	Guest        bool                `json:"is_guest"`
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

type ReqDeleteUser struct {
	Erase bool `json:"erase"`
}

// DeactivateAccount deactivates a specific local user account.
//
// https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#deactivate-account
func (cli *Client) DeactivateAccount(ctx context.Context, userID id.UserID, req ReqDeleteUser) error {
	reqURL := cli.BuildAdminURL("v1", "deactivate", userID)
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:      http.MethodPost,
		URL:         reqURL,
		RequestJSON: &req,
	})
	return err
}

type PushData struct {
	Format string `json:"format"`
	URL    string `json:"url"`
}

type ReqSetPushers struct {
	AppDisplayName    string   `json:"app_display_name"`
	AppID             string   `json:"app_id"`
	Append            bool     `json:"append"`
	Data              PushData `json:"data"`
	DeviceDisplayName string   `json:"device_display_name"`
	Kind              string   `json:"kind"`
	Lang              string   `json:"lang"`
	ProfileTag        string   `json:"profile_tag"`
	PushKey           string   `json:"pushkey"`
}

func (cli *Client) SetPushers(ctx context.Context, req ReqSetPushers) error {
	reqURL := cli.BuildClientURL("v3", "pushers", "set")
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:      http.MethodPost,
		URL:         reqURL,
		RequestJSON: &req,
	})
	return err
}

type Threepid struct {
	Medium  string `json:"medium"`
	Address string `json:"address"`
}

type ReqCreateOrModifyAccount struct {
	Password      string `json:"password,omitempty"`
	LogoutDevices *bool  `json:"logout_devices,omitempty"`

	Deactivated *bool `json:"deactivated,omitempty"`
	Admin       *bool `json:"admin,omitempty"`
	Locked      *bool `json:"locked,omitempty"`

	Displayname string              `json:"displayname,omitempty"`
	AvatarURL   id.ContentURIString `json:"avatar_url,omitempty"`
	UserType    string              `json:"user_type,omitempty"`

	Threepids []Threepid `json:"threepids,omitempty"`
}

// CreateOrModifyAccount creates or modifies an account on the server.
//
// https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#create-or-modify-account
func (cli *Client) CreateOrModifyAccount(ctx context.Context, userID id.UserID, req ReqCreateOrModifyAccount) error {
	reqURL := cli.BuildAdminURL("v2", "users", userID)
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:      http.MethodPut,
		URL:         reqURL,
		RequestJSON: &req,
	})
	return err
}

type RatelimitOverride struct {
	MessagesPerSecond int `json:"messages_per_second"`
	BurstCount        int `json:"burst_count"`
}

type ReqSetRatelimit = RatelimitOverride

// SetUserRatelimit overrides the message sending ratelimit for a specific user.
//
// https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#set-ratelimit
func (cli *Client) SetUserRatelimit(ctx context.Context, userID id.UserID, req ReqSetRatelimit) error {
	reqURL := cli.BuildAdminURL("v1", "users", userID, "override_ratelimit")
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:      http.MethodPost,
		URL:         reqURL,
		RequestJSON: &req,
	})
	return err
}

type RespUserRatelimit = RatelimitOverride

// GetUserRatelimit gets the ratelimit override for the given user.
//
// https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#get-status-of-ratelimit
func (cli *Client) GetUserRatelimit(ctx context.Context, userID id.UserID) (resp RespUserRatelimit, err error) {
	_, err = cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          cli.BuildAdminURL("v1", "users", userID, "override_ratelimit"),
		ResponseJSON: &resp,
	})
	return
}

// DeleteUserRatelimit deletes the ratelimit override for the given user, returning them to the default ratelimits.
//
// https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#delete-ratelimit
func (cli *Client) DeleteUserRatelimit(ctx context.Context, userID id.UserID) (err error) {
	_, err = cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method: http.MethodDelete,
		URL:    cli.BuildAdminURL("v1", "users", userID, "override_ratelimit"),
	})
	return
}
