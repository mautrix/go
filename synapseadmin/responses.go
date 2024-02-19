// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package synapseadmin

import (
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// RoomInfos represents the structure of each room
type RoomInfos struct {
    RoomID             id.RoomID	`json:"room_id"`
    Name               string		`json:"name"`
    CanonicalAlias     string		`json:"canonical_alias"`
    JoinedMembers      int    		`json:"joined_members"`
    JoinedLocalMembers int    		`json:"joined_local_members"`
    Version            string 		`json:"version"`
    Creator            string 		`json:"creator"`
    Encryption         string 		`json:"encryption"`
    Federatable        bool   		`json:"federatable"`
    Public             bool   		`json:"public"`
    JoinRules          string 		`json:"join_rules"`
    GuestAccess        string 		`json:"guest_access"`
    HistoryVisibility  string 		`json:"history_visibility"`
    StateEvents        int    		`json:"state_events"`
    RoomType           string 		`json:"room_type"`
}

// RoomsResponse represents the response containing a list of rooms
type RoomsResponse struct {
    Rooms      []RoomInfos `json:"rooms"`
    Offset     int    `json:"offset"`
    TotalRooms int    `json:"total_rooms"`
	NextBatch  int	  `json:"next_batch"`
}

// RoomsMembersResponse represents the response containing a list of members of a room
type RoomsMembersResponse struct {
    Members		[]string	`json:"members"`
    Total		int			`json:"total"`
}

// RoomsBlockResponse represents the response containing wether a room is blocked or not
type RoomsBlockResponse struct {
    Block		bool		`json:"block"`
    UserId		id.UserID	`json:"user_id"`
}

// https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#room-messages-api
type RespMessagesAdmin *mautrix.RespMessages
