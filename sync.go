// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

// SyncData contains everything in a single synchronization
type SyncData struct {
	NextBatch string         `json:"next_batch"`
	Rooms     SyncRooms      `json:"rooms"`
	Presence  EventContainer `json:"presence"`
	Initial   bool           `json:"-"`
}

// SyncRooms contains all joined and invited rooms
type SyncRooms struct {
	Join    map[string]SRoom       `json:"join"`
	Invited map[string]InvitedRoom `json:"invite"`
	Leave   map[string]LeftRoom    `json:"leave"`
}

// LeftRoom is a room the user has left or been banned from
type LeftRoom struct {
	// Member list and other persistent data
	State EventContainer `json:"state"`
	// Messages, state changes, etc..
	Timeline EventContainer `json:"timeline"`
}

// InvitedRoom is a room that the user has been invited to
type InvitedRoom struct {
	InviteState EventContainer `json:"invite_state"`
}

// SRoom represents a single room
type SRoom struct {
	// Typing notifications, presence updates, etc..
	Ephemeral EventContainer `json:"ephemeral"`
	// Member list and other persistent data
	State EventContainer `json:"state"`
	// Messages, state changes, etc..
	Timeline Timeline `json:"timeline"`
	// Tags and custom configs
	AccountData EventContainer `json:"account_data"`
}

// EventContainer contains an array of events
type EventContainer struct {
	Events []Event `json:"events"`
}

// Timeline wraps things in a timeline
type Timeline struct {
	EventContainer
	Limited   bool   `json:"limited"`
	PrevBatch string `json:"prev_batch"`
}

// Sync the current status with the homeserver
func (mx *MatrixBot) Sync() error {
	var req Request
	if len(mx.NextBatch) == 0 {
		req = mx.NewPlainRequest("/sync?access_token=%s&timeout=10000", mx.AccessToken)
	} else {
		req = mx.NewPlainRequest("/sync?since=%s&access_token=%s&timeout=10000", mx.NextBatch, mx.AccessToken)
	}
	creq := req.GET()
	if !creq.OK() {
		return creq.Error
	}

	data := SyncData{}
	err := creq.JSON(&data)
	if err != nil {
		return err
	}
	data.Initial = len(mx.NextBatch) == 0

	mx.NextBatch = data.NextBatch
	mx.syncPresence(data)
	mx.syncJoinedRooms(data)
	mx.syncInvitedRooms(data)
	return nil
}

func (mx *MatrixBot) syncPresence(data SyncData) {
	for _, evt := range data.Presence.Events {
		mx.Presence[evt.Sender], _ = evt.Content["presence"].(string)
	}
}

func (mx *MatrixBot) syncJoinedRooms(data SyncData) {
	for roomID, v := range data.Rooms.Join {
		room := mx.GetRoom(roomID)
		for _, event := range v.State.Events {
			switch {
			case event.Type == EvtRoomName:
				room.Name, _ = event.Content["name"].(string)
			case event.Type == EvtRoomMember:
				member, ok := room.Members[event.StateKey]
				if !ok {
					member = Member{}
				}
				member.Membership, _ = event.Content["membership"].(string)
				member.DisplayName, _ = event.Content["displayname"].(string)
				room.Members[event.StateKey] = member
			}
		}

		if !data.Initial {
			for _, event := range v.Timeline.Events {
				event.Room = room
				mx.Timeline <- event
			}
		}
	}
}

func (mx *MatrixBot) syncInvitedRooms(data SyncData) {
	for roomID, v := range data.Rooms.Invited {
		invite, old := mx.Invites[roomID]
		if !old {
			invite = &Invite{
				Session: mx,
				ID:      roomID,
				Members: make(map[string]string),
			}
		}
		for _, event := range v.InviteState.Events {
			invite.Sender = event.Sender
			switch event.Type {
			case EvtRoomMember:
				invite.Members[event.StateKey], _ = event.Content["membership"].(string)
			case EvtRoomName:
				invite.Name, _ = event.Content["name"].(string)
			}
		}
		mx.Invites[roomID] = invite
		if !old {
			mx.InviteChan <- roomID
		}
	}
}
