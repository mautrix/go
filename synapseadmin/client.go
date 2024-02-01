// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package synapseadmin

import (
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"context"
	"time"
	"maunium.net/go/mautrix/id"
	"net/http"
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

func (cli *Client) SyncRoomWithContextAdmin(ctx context.Context, nextBatch string, roomID string) error {
	// Use Admin API to pseudo sync specific room messages
	for {
		resSyncAdmin, err := cli.FullSyncRequest(ctx, ReqSyncAdmin{
			from: nextBatch,
		}, roomID)
		if err != nil {
			return err
		}
		/*
		remplacer par stockage sur fichier bbolt
		err = cli.Store.SaveNextBatch(ctx, cli.UserID, resSyncAdmin.End)
		if err != nil {
			return err
		}
		*/

		resSync := RespSyncAdminToRespSync(resSyncAdmin)
		if err = cli.Syncer.ProcessResponse(ctx, resSync, nextBatch); err != nil {
			return err
		}
		if (resSync.NextBatch != "") {
			nextBatch = resSync.NextBatch
		}
		time.Sleep(2 * time.Second)
	}
}

type ReqSyncAdmin struct {
	from	string
}

func (req *ReqSyncAdmin) BuildQuery() map[string]string {
	query := map[string]string{}
	if req.from != "" {
		query["from"] = req.from
	}
	return query
}

func RespSyncAdminToRespSync(respSyncAdmin *mautrix.RespSyncRoomMessagesAdmin) *mautrix.RespSync {
    respSync := &mautrix.RespSync{}
	respSync.NextBatch = respSyncAdmin.End
	respSync.Presence.Events = append(respSync.Presence.Events, &event.Event{Type: event.Type{Type: "RoomMessagesAdmin"}})
    // Populate Rooms field
    respSync.Rooms = mautrix.RespSyncRooms{
        Join: make(map[id.RoomID]*mautrix.SyncJoinedRoom),
    }

    // Iterate over events in Chunk and populate Join field
    for _, room_event := range respSyncAdmin.Chunk {
        roomID := room_event.RoomID
        joinedRoom, ok := respSync.Rooms.Join[roomID]
        if !ok {
            joinedRoom = &mautrix.SyncJoinedRoom{
                Timeline: mautrix.SyncTimeline{
                    SyncEventsList: mautrix.SyncEventsList{Events: []*event.Event{}},
                    Limited:        true,
                    PrevBatch:      "",
                },
            }
            respSync.Rooms.Join[roomID] = joinedRoom
        }
        joinedRoom.Timeline.Events = append(joinedRoom.Timeline.Events, room_event)
    }

    return respSync
}

func (cli *Client) FullSyncRequest(ctx context.Context, req ReqSyncAdmin, roomID string) (resp *mautrix.RespSyncRoomMessagesAdmin, err error) {
	urlPath := cli.BuildURLWithQuery(mautrix.SynapseAdminURLPath{"v1", "rooms", roomID, "messages"}, req.BuildQuery())
	fullReq := mautrix.FullRequest{
		Method:       http.MethodGet,
		URL:          urlPath,
		ResponseJSON: &resp,
		MaxAttempts: 1,
	}
	_, err = cli.MakeFullRequest(ctx, fullReq)
	return
}

