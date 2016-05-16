package goMatrix

import "log"

// Session .
type Session struct {
	NextBatch   string
	Rooms       map[string]RoomInfo // The rooms a user is part of
	AccessToken string
	HomeServer  string
	OnNewMsg    chan RoomMessage
	OnJoin      chan string // When we find a new room
	TxnID       int
	stop        chan bool // stop the service
}

// Start ..
func (session *Session) Start() {
	go func() {
	Loop:
		for {
			select {
			case <-session.stop:
				break Loop
			default:
				err := session.Sync()
				if err != nil {
					switch {
					case err.Error()[(len(err.Error())-11):] == "i/o timeout": // Just ignore this one
					default:
						log.Println(err)
					}
				}
			}
		}
	}()
}

// Close closes everything down
func (session *Session) Close() {
	session.stop <- true
}

// Init .
func Init(homeserver string) *Session {
	session := Session{HomeServer: homeserver,
		NextBatch: "s9_13_0_1_1_1",
		OnNewMsg:  make(chan RoomMessage, 10),
		OnJoin:    make(chan string, 10),
		Rooms:     make(map[string]RoomInfo),
		TxnID:     0,
		stop:      make(chan bool),
	}

	return &session
}
