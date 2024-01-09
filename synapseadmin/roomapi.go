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

//  Get room info based on alias
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html
func (cli *Client) ListRoom(ctx context.Context, alias string) (*mautrix.RoomsResponse ,error) {
	reqURL := cli.BuildURLWithQuery(mautrix.SynapseAdminURLPath{"v1", "rooms"}, map[string]string{"search_term": alias})
	var resp mautrix.RoomsResponse
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          reqURL,
		ResponseJSON: &resp,
	})
	return &resp, err
}

// ReqDeleteRoom is the request content for Client.DeleteRoom.
type ReqDeleteRoom struct {
	// Room Id to delete
	RoomId string `json:"room_id"`
	// Default to true: remove all traces from database
	Purge bool `json:"purge"`
}

//  Delete Room based on Id
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#version-2-new-version
func (cli *Client) DeleteRoom(ctx context.Context, req ReqDeleteRoom) error {
	reqURL := cli.BuildAdminURL("v2", "rooms", req.RoomId)
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodDelete,
		URL:          reqURL,
		RequestJSON: &req,
	})
	return err
}

// Get Room Members based on Room Id
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#version-2-new-version
func (cli *Client) RoomMembers(ctx context.Context, RoomId string) (*mautrix.RoomsMembersResponse, error) {
	reqURL := cli.BuildAdminURL("v1", "rooms", RoomId, "members")
	var resp mautrix.RoomsMembersResponse
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          reqURL,
		ResponseJSON: &resp,
	})
	return &resp, err
}

// ReqRoomAdmin is the request content for Client.RoomAdmin.
type ReqRoomAdmin struct {
	// User Id to make admin
	UserId id.UserID `json:"user_id"`
	// Room Id or alias
	Room string `json:"room"`
}

//  Make admin a Room's user based on Id
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#make-room-admin-api
func (cli *Client) RoomAdmin(ctx context.Context, req ReqRoomAdmin) error {
	reqURL := cli.BuildAdminURL("v1", "rooms", req.Room, "make_room_admin")
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodPost,
		URL:          reqURL,
		RequestJSON: &req,
	})
	return err
}

// ReqAddUser is the request content for Client.AddUser.
type ReqAddUser struct {
	// User Id to make admin
	UserId string `json:"user_id"`
	// Room Id or alias
	Room string `json:"room"`
}

//  Add User to Room
//
// https://matrix-org.github.io/synapse/latest/admin_api/room_membership.html
func (cli *Client) AddUser(ctx context.Context, req ReqAddUser) error {
	reqURL := cli.BuildAdminURL("v1", "join", req.Room)
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodPost,
		URL:          reqURL,
		RequestJSON: &req,
	})
	return err
}

// ReqBlockRoom is the request content for Client.BlockRoom.
type ReqBlockRoom struct {
	// Room Id to block
	RoomId string `json:"room_id"`
	// true to block
	Block bool `json:"block"`
}

//  Block or UnBlock a Room
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#block-room-api
func (cli *Client) BlockRoom(ctx context.Context, req ReqBlockRoom) error {
	reqURL := cli.BuildAdminURL("v1", "rooms", req.RoomId, "block")
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodPut,
		URL:          reqURL,
		RequestJSON: &req,
	})
	return err
}

//  Get block status of a Room
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#get-block-status
func (cli *Client) GetBlockRoom(ctx context.Context, RoomId string) (*mautrix.RoomsBlockResponse, error) {
	var resp mautrix.RoomsBlockResponse
	reqURL := cli.BuildAdminURL("v1", "rooms", RoomId, "block")
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          reqURL,
		ResponseJSON: &resp,
	})
	return &resp, err
}
