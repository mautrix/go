// mautrix - A Matrix client-server library intended for bots.
// Copyright (C) 2017 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package mautrix

// EventContent contains the name and body of an event
type EventContent struct {
	Name string `json:"name"`
	Body string `json:"body"`
}

// Unsigned contains the unsigned event contents
type Unsigned struct {
	InviteRoomState []Event `json:"invite_room_state"`
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
	TransactionID    string                 `json:"txn_id"`
	Unsigned         Unsigned               `json:"unsigned"`

	Room *Room `json:"-"`
}

// CanMarkRead checks if the event can be marked as read
func (evt Event) CanMarkRead() bool {
	return len(evt.ID) > 0
}

// MarkRead marks this event as read
func (evt Event) MarkRead() bool {
	if evt.CanMarkRead() {
		creq := evt.Room.Session.NewPlainRequest(
			"/rooms/%s/receipt/%s/%s?access_token=%s",
			evt.Room.ID, EvtRead, evt.ID, evt.Room.Session.AccessToken).POST()
		return creq.CheckStatusOK()
	}
	return false
}
