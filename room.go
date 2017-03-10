package mautrix

import (
	"fmt"
)

// Invite wraps an invite to a room
type Invite struct {
	Sender  string
	Name    string
	ID      string
	Members map[string]string
	Session *Session
}

// Member contains some information about a room member
type Member struct {
	Membership  string
	Power       int
	DisplayName string
}

// Room is a room
type Room struct {
	ID      string
	Name    string
	Members map[string]Member
	Aliases []string
	Session *Session
}

// SendResponse wraps the response to a room send request
type SendResponse struct {
	EventID   string `json:"event_id"`
	Error     string `json:"error"`
	ErrorCode string `json:"errcode"`
}

// Send a message to this room
func (r *Room) Send(message string) error {
	creq := r.Session.NewJSONRequest(
		map[string]string{
			"msgtype": MsgText,
			"body":    message,
		},
		"/rooms/%s/send/%s/%s?access_token=%s",
		r.ID, EvtRoomMessage, GenerateNonce(), r.Session.AccessToken,
	).PUT()
	if !creq.OK() {
		return creq.Error
	}

	var data SendResponse
	err := creq.JSON(&data)
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
	creq := s.NewPlainRequest(
		"/rooms/%s/join?access_token=%s",
		roomID, s.AccessToken,
	).POST()
	if !creq.OK() {
		return creq.Error
	} else if !creq.CheckStatusOK() {
		errstr, _ := creq.Text()
		return fmt.Errorf("HTTP %d: %s", creq.Response.StatusCode, errstr)
	}
	return nil
}

// Accept the invite
func (i Invite) Accept() error {
	return i.Session.Join(i.ID)
}
