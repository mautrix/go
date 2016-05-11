package goMatrix

import "log"

// Session .
type Session struct {
	NextBatch   string
	Rooms       map[string]RoomInfo // The rooms a user is part of
	AccessToken string
	HomeServer  string
	OnNewMsg    chan RoomMessage
	OnJoin      chan string      // When we find a new room
	TxnID       int
}

// Start ..
func (session *Session) Start() {
	go func() {
		for {
			err := session.Sync()
			if err != nil {
				log.Println(err)
			}
		}
	}()
}

// Init .
func Init(homeserver string) *Session {
	session := Session{HomeServer: homeserver,
		NextBatch: "s9_13_0_1_1_1",
		OnNewMsg:  make(chan RoomMessage, 10),
		OnJoin:    make(chan string, 10),
		Rooms:     make(map[string]RoomInfo),
		TxnID:     0,
	}

	return &session
}
