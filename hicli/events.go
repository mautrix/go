// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package hicli

import (
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/hicli/database"
	"maunium.net/go/mautrix/id"
)

type SyncRoom struct {
	Meta     *database.Room                                `json:"meta"`
	Timeline []database.TimelineRowTuple                   `json:"timeline"`
	State    map[event.Type]map[string]database.EventRowID `json:"state"`
	Events   []*database.Event                             `json:"events"`
	Reset    bool                                          `json:"reset"`
}

type SyncComplete struct {
	Rooms map[id.RoomID]*SyncRoom `json:"rooms"`
}

func (c *SyncComplete) IsEmpty() bool {
	return len(c.Rooms) == 0
}

type EventsDecrypted struct {
	RoomID            id.RoomID           `json:"room_id"`
	PreviewEventRowID database.EventRowID `json:"preview_event_rowid,omitempty"`
	Events            []*database.Event   `json:"events"`
}

type Typing struct {
	RoomID id.RoomID `json:"room_id"`
	event.TypingEventContent
}

type SendComplete struct {
	Event *database.Event `json:"event"`
	Error error           `json:"error"`
}

type ClientState struct {
	IsLoggedIn    bool        `json:"is_logged_in"`
	IsVerified    bool        `json:"is_verified"`
	UserID        id.UserID   `json:"user_id,omitempty"`
	DeviceID      id.DeviceID `json:"device_id,omitempty"`
	HomeserverURL string      `json:"homeserver_url,omitempty"`
}
