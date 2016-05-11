package goMatrix

import (
	"encoding/json"
	"net/http"
)

type syncData struct {
	NextBatch string `json:"next_batch"`
	Rooms     rooms  `json:"rooms"`
	// Presence presence `json:"presence"`
}

// type Presence struct {
//
// }

type rooms struct {
	Join map[string]roomIDs `json:"join"`
}

type roomIDs struct {
	Ephemeral ephemeral `json:"ephemeral"`
	State     state     `json:"state"`
	Timeline  timeline  `json:"timeline"`
}

// ephemeral = things like typing notifications, and presence updates
type ephemeral struct {
	Events []event `json:"events"`
}

// timeline = stuff in the room timeline itself, e.g. messages. also includes state changes.
type timeline struct {
	Events []event `json:"events"`
}

// state = persistent key/value pair data about the room (e.g. its name)
type state struct {
	Events []event `json:"events"`
}

type event struct {
	Type     string       `json:"type"`
	Content  eventContent `json:"content"`
	Unsigned unsigned     `json:"unsigned"`
	Sender   string       `json:"sender"`
}

type eventContent struct {
	Name string `json:"name"`
	Body string `json:"body"`
}

type unsigned struct {
	InviteRoomState []event `json:"invite_room_state"`
}

// Sync .
func (session *Session) Sync() error {
	resp, err := http.Get(session.HomeServer + "/_matrix/client/r0/sync?since=" + session.NextBatch + "&access_token=" + session.AccessToken + "&timeout=10000")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data := syncData{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return err
	}

	session.NextBatch = data.NextBatch

	for roomID, v := range data.Rooms.Join { // Look trough all the rooms

		for _, event := range v.State.Events { // Look torugh all events in state
			switch {
			case event.Type == "m.room.name":
				_, ok := session.Rooms[roomID]
				if !ok {
					session.Rooms[roomID] = RoomInfo{Name: event.Content.Name}
					session.OnJoin <- event.Content.Name
				}
			}
		}

		for _, event := range v.Timeline.Events { // Look torugh all events on timeline
			switch {
			case event.Type == "m.room.message":
				roomInfo := session.Rooms[roomID]
				session.OnNewMsg <- RoomMessage{RoomID: roomID,
					RoomName: roomInfo.Name,
					Sender:   event.Sender,
					Text:     event.Content.Body,
				}
			}
		}

	}
	return nil
}
