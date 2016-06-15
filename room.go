package mautrix

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RoomInfo - Information about a room
type RoomInfo struct {
	Name string
}

// SendResponse wraps the response to a room send request
type SendResponse struct {
	EventID   string `json:"event_id"`
	Error     string `json:"error"`
	ErrorCode string `json:"errcode"`
}

// RoomNameToID - get the room id from a room name
func (session *Session) RoomNameToID(roomName string) string {
	for k, v := range session.Rooms {
		if v.Name == roomName {
			return k
		}
	}

	return ""
}

// SendToRoom - Send message to room
func (session *Session) SendToRoom(room, message string) error {
	resp, err := JSONPOST(session.GetURL(
		"/rooms/%s/send/%s/%s?access_token=%s",
		room, EvtRoomMessage, GenerateNonce(), session.AccessToken,
	), fmt.Sprintf(
		"{\"msgtype\": \"%s\", \"body\":\"%s\"}",
		MsgText, strings.Replace(message, "\"", "\\\"", -1),
	))
	if err != nil {
		return err
	}

	var data SendResponse
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return err
	} else if len(data.Error) > 0 {
		return fmt.Errorf(data.Error)
	} else if len(data.EventID) == 0 {
		return fmt.Errorf("No event ID received!")
	}
	return nil
}
