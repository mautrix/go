package mautrix

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// RoomInfo - Information about a room
type RoomInfo struct {
	Name string
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
	message = strings.Replace(message, "\"", "\\\"", -1) // fix for " in messages
	resp, err := JSONPOST(session.GetURL(
		"/rooms/%s/send/%s/%s?access_token=%s",
		room, EvtRoomMessage, GenerateNonce(), session.AccessToken,
	), fmt.Sprintf(
		"{\"msgtype\": \"%s\", \"body\":\"%s\"}",
		MsgText, message,
	))
	if err != nil {
		return err
	}

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return err
	}
	Error, ok := data["error"]
	if ok {
		return errors.New(Error.(string))
	}

	// fmt.Println(data)

	// TODO: Check that the response is what we expected

	return nil
}
