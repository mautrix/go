package mautrix

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SyncData contains everything in a single synchronization
type SyncData struct {
	NextBatch string `json:"next_batch"`
	Rooms     Rooms  `json:"rooms"`
	// Presence presence `json:"presence"`
}

// type Presence struct {
//
// }

// Rooms contains all joined and invited rooms
type Rooms struct {
	Join   map[string]Room `json:"join"`
	Invite map[string]Room `json:"invite"`
	Leave  map[string]Room `json:"leave"`
}

// Room represents a single room
type Room struct {
	// Typing notifications, presence updates, etc..
	Ephemeral EventContainer `json:"ephemeral"`
	// Member list and other persistent data
	State EventContainer `json:"state"`
	// Messages, state changes, etc..
	Timeline EventContainer `json:"timeline"`
	// Tags and custom configs
	AccountData EventContainer `json:"account_data"`
}

// EventContainer contains an array of events
type EventContainer struct {
	Events    []Event `json:"events"`
	Limited   bool    `json:"limited"`
	PrevBatch string  `json:"prev_batch"`
}

// Event represents a single event
type Event struct {
	ID               string                 `json:"event_id"`
	Type             string                 `json:"type"`
	Sender           string                 `json:"sender"`
	Content          map[string]interface{} `json:"content"`
	OriginServerTime int64                  `json:"origin_server_ts"`
	Age              int64                  `json:"age"`
	Nonce            string                 `json:"txn_id"`
	Unsigned         Unsigned               `json:"unsigned"`

	RoomID string `json:"-"`
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

// Sync .
func (session *Session) Sync() error {
	resp, err := http.Get(session.GetURL("/sync?since=%s&access_token=%s&timeout=10000", session.NextBatch, session.AccessToken))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data := SyncData{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return err
	}

	session.NextBatch = data.NextBatch

	for roomID, v := range data.Rooms.Join {
		for _, event := range v.State.Events {
			switch {
			case event.Type == EvtRoomName:
				_, ok := session.Rooms[roomID]
				if !ok {
					name, _ := event.Content["name"].(string)
					session.Rooms[roomID] = RoomInfo{Name: name}
					session.OnJoin <- name
				}
			}
		}

		for _, event := range v.Timeline.Events {
			event.RoomID = roomID
			session.Timeline <- event
			resp, err := POST(session.GetURL("/rooms/%s/receipt/%s/%s?access_token=%s", roomID, EvtRead, event.ID, session.AccessToken))
			if resp.StatusCode != http.StatusOK {
				fmt.Printf("Failed to mark message %s in room %s as read (HTTP %d): %s\n", event.ID, roomID, resp.StatusCode, err)
			}
		}
	}
	return nil
}
