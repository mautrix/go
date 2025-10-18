// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package synapseadmin

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type ReqListRoom struct {
	SearchTerm string
	OrderBy    string
	Direction  mautrix.Direction
	From       int
	Limit      int
}

func (req *ReqListRoom) BuildQuery() map[string]string {
	query := map[string]string{
		"from": strconv.Itoa(req.From),
	}
	if req.SearchTerm != "" {
		query["search_term"] = req.SearchTerm
	}
	if req.OrderBy != "" {
		query["order_by"] = req.OrderBy
	}
	if req.Direction != 0 {
		query["dir"] = string(req.Direction)
	}
	if req.Limit != 0 {
		query["limit"] = strconv.Itoa(req.Limit)
	}
	return query
}

type RoomInfo struct {
	RoomID             id.RoomID               `json:"room_id"`
	Name               string                  `json:"name"`
	CanonicalAlias     id.RoomAlias            `json:"canonical_alias"`
	JoinedMembers      int                     `json:"joined_members"`
	JoinedLocalMembers int                     `json:"joined_local_members"`
	Version            string                  `json:"version"`
	Creator            id.UserID               `json:"creator"`
	Encryption         id.Algorithm            `json:"encryption"`
	Federatable        bool                    `json:"federatable"`
	Public             bool                    `json:"public"`
	JoinRules          event.JoinRule          `json:"join_rules"`
	GuestAccess        event.GuestAccess       `json:"guest_access"`
	HistoryVisibility  event.HistoryVisibility `json:"history_visibility"`
	StateEvents        int                     `json:"state_events"`
	RoomType           event.RoomType          `json:"room_type"`
}

type RespListRooms struct {
	Rooms      []RoomInfo `json:"rooms"`
	Offset     int        `json:"offset"`
	TotalRooms int        `json:"total_rooms"`
	NextBatch  int        `json:"next_batch"`
	PrevBatch  int        `json:"prev_batch"`
}

// ListRooms returns a list of rooms on the server.
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#list-room-api
func (cli *Client) ListRooms(ctx context.Context, req ReqListRoom) (RespListRooms, error) {
	var resp RespListRooms
	var reqURL string
	reqURL = cli.Client.BuildURLWithQuery(mautrix.SynapseAdminURLPath{"v1", "rooms"}, req.BuildQuery())
	_, err := cli.Client.MakeRequest(ctx, http.MethodGet, reqURL, nil, &resp)
	return resp, err
}

func (cli *Client) RoomInfo(ctx context.Context, roomID id.RoomID) (resp *RoomInfo, err error) {
	reqURL := cli.BuildAdminURL("v1", "rooms", roomID)
	_, err = cli.Client.MakeRequest(ctx, http.MethodGet, reqURL, nil, &resp)
	return
}

type RespRoomMessages = mautrix.RespMessages

// RoomMessages returns a list of messages in a room.
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#room-messages-api
func (cli *Client) RoomMessages(ctx context.Context, roomID id.RoomID, from, to string, dir mautrix.Direction, filter *mautrix.FilterPart, limit int) (resp *RespRoomMessages, err error) {
	query := map[string]string{
		"from": from,
		"dir":  string(dir),
	}
	if filter != nil {
		filterJSON, err := json.Marshal(filter)
		if err != nil {
			return nil, err
		}
		query["filter"] = string(filterJSON)
	}
	if to != "" {
		query["to"] = to
	}
	if limit != 0 {
		query["limit"] = strconv.Itoa(limit)
	}
	urlPath := cli.Client.BuildURLWithQuery(mautrix.SynapseAdminURLPath{"v1", "rooms", roomID, "messages"}, query)
	_, err = cli.Client.MakeRequest(ctx, http.MethodGet, urlPath, nil, &resp)
	return resp, err
}

type ReqDeleteRoom struct {
	Purge         bool      `json:"purge,omitempty"`
	ForcePurge    bool      `json:"force_purge,omitempty"`
	Block         bool      `json:"block,omitempty"`
	Message       string    `json:"message,omitempty"`
	RoomName      string    `json:"room_name,omitempty"`
	NewRoomUserID id.UserID `json:"new_room_user_id,omitempty"`
}

type RespDeleteRoom struct {
	DeleteID string `json:"delete_id"`
}

type RespDeleteRoomResult struct {
	KickedUsers       []id.UserID    `json:"kicked_users,omitempty"`
	FailedToKickUsers []id.UserID    `json:"failed_to_kick_users,omitempty"`
	LocalAliases      []id.RoomAlias `json:"local_aliases,omitempty"`
	NewRoomID         id.RoomID      `json:"new_room_id,omitempty"`
}

type RespDeleteRoomStatus struct {
	Status       string               `json:"status,omitempty"`
	Error        string               `json:"error,omitempty"`
	ShutdownRoom RespDeleteRoomResult `json:"shutdown_room,omitempty"`
}

// DeleteRoom deletes a room from the server, optionally blocking it and/or purging all data from the database.
//
// This calls the async version of the endpoint, which will return immediately and delete the room in the background.
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#version-2-new-version
func (cli *Client) DeleteRoom(ctx context.Context, roomID id.RoomID, req ReqDeleteRoom) (RespDeleteRoom, error) {
	reqURL := cli.BuildAdminURL("v2", "rooms", roomID)
	var resp RespDeleteRoom
	_, err := cli.Client.MakeRequest(ctx, http.MethodDelete, reqURL, &req, &resp)
	return resp, err
}

func (cli *Client) DeleteRoomStatus(ctx context.Context, deleteID string) (resp RespDeleteRoomStatus, err error) {
	reqURL := cli.BuildAdminURL("v2", "rooms", "delete_status", deleteID)
	_, err = cli.Client.MakeRequest(ctx, http.MethodGet, reqURL, nil, &resp)
	return
}

// DeleteRoomSync deletes a room from the server, optionally blocking it and/or purging all data from the database.
//
// This calls the synchronous version of the endpoint, which will block until the room is deleted.
//
// https://element-hq.github.io/synapse/latest/admin_api/rooms.html#version-1-old-version
func (cli *Client) DeleteRoomSync(ctx context.Context, roomID id.RoomID, req ReqDeleteRoom) (resp RespDeleteRoomResult, err error) {
	reqURL := cli.BuildAdminURL("v1", "rooms", roomID)
	httpClient := &http.Client{}
	_, err = cli.Client.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:       http.MethodDelete,
		URL:          reqURL,
		RequestJSON:  &req,
		ResponseJSON: &resp,
		MaxAttempts:  1,
		// Use a fresh HTTP client without timeouts
		Client: httpClient,
	})
	httpClient.CloseIdleConnections()
	return
}

type RespRoomsMembers struct {
	Members []id.UserID `json:"members"`
	Total   int         `json:"total"`
}

// RoomMembers gets the full list of members in a room.
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#room-members-api
func (cli *Client) RoomMembers(ctx context.Context, roomID id.RoomID) (RespRoomsMembers, error) {
	reqURL := cli.BuildAdminURL("v1", "rooms", roomID, "members")
	var resp RespRoomsMembers
	_, err := cli.Client.MakeRequest(ctx, http.MethodGet, reqURL, nil, &resp)
	return resp, err
}

type ReqMakeRoomAdmin struct {
	UserID id.UserID `json:"user_id"`
}

// MakeRoomAdmin promotes a user to admin in a room. This requires that a local user has permission to promote users in the room.
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#make-room-admin-api
func (cli *Client) MakeRoomAdmin(ctx context.Context, roomIDOrAlias string, req ReqMakeRoomAdmin) error {
	reqURL := cli.BuildAdminURL("v1", "rooms", roomIDOrAlias, "make_room_admin")
	_, err := cli.Client.MakeRequest(ctx, http.MethodPost, reqURL, &req, nil)
	return err
}

type ReqJoinUserToRoom struct {
	UserID id.UserID `json:"user_id"`
}

// JoinUserToRoom makes a local user join the given room.
//
// https://matrix-org.github.io/synapse/latest/admin_api/room_membership.html
func (cli *Client) JoinUserToRoom(ctx context.Context, roomID id.RoomID, req ReqJoinUserToRoom) error {
	reqURL := cli.BuildAdminURL("v1", "join", roomID)
	_, err := cli.Client.MakeRequest(ctx, http.MethodPost, reqURL, &req, nil)
	return err
}

type ReqBlockRoom struct {
	Block bool `json:"block"`
}

// BlockRoom blocks or unblocks a room.
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#block-room-api
func (cli *Client) BlockRoom(ctx context.Context, roomID id.RoomID, req ReqBlockRoom) error {
	reqURL := cli.BuildAdminURL("v1", "rooms", roomID, "block")
	_, err := cli.Client.MakeRequest(ctx, http.MethodPut, reqURL, &req, nil)
	return err
}

// RoomsBlockResponse represents the response containing wether a room is blocked or not
type RoomsBlockResponse struct {
	Block  bool      `json:"block"`
	UserID id.UserID `json:"user_id"`
}

// GetRoomBlockStatus gets whether a room is currently blocked.
//
// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#get-block-status
func (cli *Client) GetRoomBlockStatus(ctx context.Context, roomID id.RoomID) (RoomsBlockResponse, error) {
	var resp RoomsBlockResponse
	reqURL := cli.BuildAdminURL("v1", "rooms", roomID, "block")
	_, err := cli.Client.MakeRequest(ctx, http.MethodGet, reqURL, nil, &resp)
	return resp, err
}
