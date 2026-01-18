package continuwuityadmin

import (
	"context"
	"net/http"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// RespGetRooms represents the response for `GET /_continuwuity/admin/rooms/list`.
type RespGetRooms struct {
	Rooms []id.RoomID `json:"rooms"`
}

// ReqBanRoom represents the request body for `PUT /_continuwuity/admin/rooms/{room_id}/ban`.
type ReqBanRoom struct {
	RoomID id.RoomID `json:"room_id"`
	Banned bool      `json:"banned"`
}

// RespBanRoom represents the response for `PUT /_continuwuity/admin/rooms/{room_id}/ban`.
type RespBanRoom struct {
	KickedUsers       []id.UserID    `json:"kicked_users"`
	FailedKickedUsers []id.UserID    `json:"failed_kicked_users"`
	LocalAliases      []id.RoomAlias `json:"local_aliases"`
}

// ListRooms retrieves a list of all room IDs known to the server (excluding banned rooms).
func (cli *Client) ListRooms(ctx context.Context) (resp *RespGetRooms, err error) {
	reqURL := cli.Client.BuildURL(mautrix.ContinuwuityAdminURLPath{"rooms", "list"})
	_, err = cli.Client.MakeRequest(ctx, http.MethodGet, reqURL, nil, &resp)
	return resp, err
}

// BanRoom bans a room.
//
// This will first remove all local users, and then remove all local aliases,
// returning a list of users that were removed, failed to be removed, and aliases
// that were removed.
//
// This operation may take a long time.
func (cli *Client) BanRoom(ctx context.Context, roomID id.RoomID) (resp *RespBanRoom, err error) {
	body := ReqBanRoom{
		RoomID: roomID,
		Banned: true,
	}
	reqURL := cli.Client.BuildURL(mautrix.ContinuwuityAdminURLPath{"rooms", roomID, "ban"})
	_, err = cli.Client.MakeRequest(ctx, http.MethodPost, reqURL, &body, &resp)
	return resp, err
}

// UnbanRoom unbans a room.
func (cli *Client) UnbanRoom(ctx context.Context, roomID id.RoomID) (resp *RespBanRoom, err error) {
	body := ReqBanRoom{
		RoomID: roomID,
		Banned: false,
	}
	reqURL := cli.Client.BuildURL(mautrix.ContinuwuityAdminURLPath{"rooms", roomID, "ban"})
	_, err = cli.Client.MakeRequest(ctx, http.MethodPost, reqURL, &body, &resp)
	return resp, err
}
