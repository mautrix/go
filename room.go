package goMatrix

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// RoomInfo - Information about a room
type RoomInfo struct {
	Name string
}

// RoomMessage - Message from a room
type RoomMessage struct {
	RoomID   string
	RoomName string
	Sender   string
	Text     string
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
	jsTest := "{\"msgtype\":\"m.text\", \"body\":\"" + message + "\"}"

	url := session.HomeServer + "/_matrix/client/r0/rooms/" + room + "/send/m.room.message/" + strconv.Itoa(session.TxnID) + "?access_token=" + session.AccessToken
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer([]byte(jsTest)))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	session.TxnID++

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
