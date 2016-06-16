package mautrix

import (
	"fmt"
)

// Session is a client-server Matrix session
type Session struct {
	NextBatch   string
	Rooms       map[string]*Room
	Invites     map[string]*Invite
	Presence    map[string]string
	AccessToken string
	MatrixID    string
	HomeServer  string
	Timeline    chan Event
	InviteChan  chan string
	JoinChan    chan string
	stop        chan bool
}

// Listen for updates from the homeserver
func (session *Session) Listen() {
Loop:
	for {
		select {
		case <-session.stop:
			break Loop
		default:
			err := session.Sync()
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}

// Stop the listener
func (session *Session) Stop() {
	session.stop <- true
}

// GetURL gets the URL for the given path on this session.
func (session *Session) GetURL(path string, args ...interface{}) string {
	return fmt.Sprintf("%s/_matrix/client/r0%s", session.HomeServer, fmt.Sprintf(path, args...))
}

// Create a Session
func Create(homeserver string) *Session {
	session := Session{HomeServer: homeserver,
		NextBatch:  "s9_13_0_1_1_1",
		Timeline:   make(chan Event, 10),
		InviteChan: make(chan string, 10),
		JoinChan:   make(chan string, 10),
		Invites:    make(map[string]*Invite),
		Rooms:      make(map[string]*Room),
		stop:       make(chan bool),
	}

	return &session
}
