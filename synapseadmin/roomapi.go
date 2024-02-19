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
	"strconv"
)

type ReqListRoom struct {
	SearchTerm	string
	From		int
	Limit		int
}

func (req *ReqListRoom) BuildQuery() map[string]string {
	query := map[string]string{
		"from": strconv.Itoa(req.From),
	}
	if req.SearchTerm != "" {
		query["search_term"] = req.SearchTerm
	}
	if req.Limit != 0 {
		query["limit"] = strconv.Itoa(req.Limit)
	}
	return query
}

//  Get room info based on room alias name
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html
func (cli *Client) ListRoom(ctx context.Context, req ReqListRoom) (RoomsResponse ,error) {
	var resp RoomsResponse
	var reqURL string
	reqURL = cli.BuildURLWithQuery(mautrix.SynapseAdminURLPath{"v1", "rooms"}, req.BuildQuery())
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          reqURL,
		ResponseJSON: &resp,
	})
	return resp, err
}

// ReqDeleteRoom is the request content for Client.DeleteRoom.
type ReqDeleteRoom struct {
	// Default to true: remove all traces from database
	Purge bool `json:"purge"`
}

//  Delete Room based on Id
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#version-2-new-version
func (cli *Client) DeleteRoom(ctx context.Context, roomID id.RoomID, req ReqDeleteRoom) error {
	reqURL := cli.BuildAdminURL("v2", "rooms", roomID)
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
func (cli *Client) RoomMembers(ctx context.Context, roomId id.RoomID) (RoomsMembersResponse, error) {
	reqURL := cli.BuildAdminURL("v1", "rooms", roomId, "members")
	var resp RoomsMembersResponse
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          reqURL,
		ResponseJSON: &resp,
	})
	return resp, err
}

// ReqRoomAdmin is the request content for Client.RoomAdmin.
type ReqRoomAdmin struct {
	// User Id to make admin
	userID id.UserID `json:"user_id"`
}

//  Make admin a Room's user based on room Id or room alias
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#make-room-admin-api
func (cli *Client) RoomAdmin(ctx context.Context, room string, req ReqRoomAdmin) error {
	reqURL := cli.BuildAdminURL("v1", "rooms", room, "make_room_admin")
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
	UserID id.UserID `json:"user_id"`
}

//  Add User to Room via room ID or room Alias
//
// https://matrix-org.github.io/synapse/latest/admin_api/room_membership.html
func (cli *Client) AddUser(ctx context.Context, room id.RoomID, req ReqAddUser) error {
	reqURL := cli.BuildAdminURL("v1", "join", room)
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodPost,
		URL:          reqURL,
		RequestJSON: &req,
	})
	return err
}

// ReqBlockRoom is the request content for Client.BlockRoom.
type ReqBlockRoom struct {
	// true to block
	Block bool `json:"block"`
}

//  Block or UnBlock a Room
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#block-room-api
func (cli *Client) BlockRoom(ctx context.Context, roomID id.RoomID, req ReqBlockRoom) error {
	reqURL := cli.BuildAdminURL("v1", "rooms", roomID, "block")
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
func (cli *Client) GetBlockRoom(ctx context.Context, roomID id.RoomID) (RoomsBlockResponse, error) {
	var resp RoomsBlockResponse
	reqURL := cli.BuildAdminURL("v1", "rooms", roomID, "block")
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          reqURL,
		ResponseJSON: &resp,
	})
	return resp, err
}
