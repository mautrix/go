package mautrix

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// Invite wraps an invite to a room
type Invite struct {
	Sender  string
	Name    string
	ID      string
	Members map[string]string
	Session *Session
}

// Room is a room
type Room struct {
	ID      string
	Name    string
	Members map[string]int
	Session *Session
	Aliases []string
}

// SendResponse wraps the response to a room send request
type SendResponse struct {
	EventID   string `json:"event_id"`
	Error     string `json:"error"`
	ErrorCode string `json:"errcode"`
}

// Send a message to this room
func (r *Room) Send(message string) error {
	resp, err := JSONPOST(r.Session.GetURL(
		"/rooms/%s/send/%s/%s?access_token=%s",
		r.ID, EvtRoomMessage, GenerateNonce(), r.Session.AccessToken,
	), fmt.Sprintf(
		"{\"msgtype\": \"%s\", \"body\":\"%s\"}",
		MsgText, strings.Replace(message, "\"", "\\\"", -1),
	))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

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

// Join a room
func (s *Session) Join(roomID string) error {
	resp, err := POST(s.GetURL("/rooms/%s/join?access_token=%s", roomID, s.AccessToken))
	defer resp.Body.Close()
	if err != nil {
		return err
	} else if resp.StatusCode != http.StatusOK {
		errstr, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errstr)
	}
	return nil
}

// Accept the invite
func (i Invite) Accept() error {
	return i.Session.Join(i.ID)
}
