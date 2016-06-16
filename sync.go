package mautrix

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SyncData contains everything in a single synchronization
type SyncData struct {
	NextBatch string         `json:"next_batch"`
	Rooms     SyncRooms      `json:"rooms"`
	Presence  EventContainer `json:"presence"`
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

// Event represents a single event
type Event struct {
	ID               string                 `json:"event_id"`
	Type             string                 `json:"type"`
	Sender           string                 `json:"sender"`
	StateKey         string                 `json:"state_key"`
	Content          map[string]interface{} `json:"content"`
	OriginServerTime int64                  `json:"origin_server_ts"`
	Age              int64                  `json:"age"`
	Nonce            string                 `json:"txn_id"`
	Unsigned         Unsigned               `json:"unsigned"`

	Room *Room `json:"-"`
}

// EventContent contains the name and body of an event
type EventContent struct {
	Name string `json:"name"`
	Body string `json:"body"`
}

// Unsigned contains the unsigned event contents
type Unsigned struct {
	InviteRoomState []Event `json:"invite_room_state"`
}

// Sync the current status with the homeserver
func (s *Session) Sync() error {
	resp, err := http.Get(s.GetURL("/sync?since=%s&access_token=%s&timeout=10000", s.NextBatch, s.AccessToken))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data := SyncData{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return err
	}

	s.NextBatch = data.NextBatch
	s.syncPresence(data)
	s.syncJoinedRooms(data)
	s.syncInvitedRooms(data)
	return nil
}

func (s *Session) syncPresence(data SyncData) {
	for _, evt := range data.Presence.Events {
		s.Presence[evt.Sender], _ = evt.Content["presence"].(string)
	}
}

func (s *Session) syncJoinedRooms(data SyncData) {
	for roomID, v := range data.Rooms.Join {
		room, ok := s.Rooms[roomID]
		if !ok {
			room = &Room{Session: s, ID: roomID, Members: make(map[string]Member)}
			s.Rooms[roomID] = room
		}
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

		for _, event := range v.Timeline.Events {
			event.Room = room
			s.Timeline <- event
			if len(event.ID) > 0 {
				resp, err := POST(s.GetURL("/rooms/%s/receipt/%s/%s?access_token=%s", roomID, EvtRead, event.ID, s.AccessToken))
				if resp.StatusCode != http.StatusOK {
					fmt.Printf("Failed to mark message %s in room %s as read (HTTP %d): %s\n", event.ID, roomID, resp.StatusCode, err)
				}
			}
		}
	}
}

func (s *Session) syncInvitedRooms(data SyncData) {
	for roomID, v := range data.Rooms.Invited {
		invite, old := s.Invites[roomID]
		if !old {
			invite = &Invite{
				Session: s,
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
		s.Invites[roomID] = invite
		if !old {
			s.InviteChan <- roomID
		}
	}
}
