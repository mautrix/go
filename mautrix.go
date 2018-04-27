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

import (
	"fmt"
	"time"
)

// MatrixBot is a client-server Matrix session
type MatrixBot struct {
	NextBatch   string
	Rooms       map[string]*Room
	Invites     map[string]*Invite
	Presence    map[string]string
	AccessToken string
	MatrixID    string
	HomeServer  string
	TxnID       int
	Timeline    chan Event
	InviteChan  chan string
	JoinChan    chan string
	stop        chan bool
}

// Listen for updates from the homeserver
func (mx *MatrixBot) Listen() {
	sleepTime := 1 * time.Second
Loop:
	for {
		select {
		case <-mx.stop:
			break Loop
		default:
			err := mx.Sync()
			if err != nil {
				fmt.Println(err)
				time.Sleep(sleepTime)
				if sleepTime < 60 * time.Second {
					sleepTime += 1 * time.Second
				}
			}
		}
	}
}

// Stop the listener
func (mx *MatrixBot) Stop() {
	mx.stop <- true
}

// GetURL gets the URL for the given path on this session
func (mx *MatrixBot) GetURL(path string, args ...interface{}) string {
	return fmt.Sprintf("%s/_matrix/client/r0%s", mx.HomeServer, fmt.Sprintf(path, args...))
}

// NextTransactionID returns the next message transaction ID
func (mx *MatrixBot) NextTransactionID() int {
	mx.TxnID++
	return mx.TxnID
}

// Create a Session
func Create(homeserver string) *MatrixBot {
	mx := MatrixBot{HomeServer: homeserver,
		Timeline:   make(chan Event, 10),
		InviteChan: make(chan string, 10),
		JoinChan:   make(chan string, 10),
		Presence:   make(map[string]string),
		Invites:    make(map[string]*Invite),
		Rooms:      make(map[string]*Room),
		stop:       make(chan bool),
	}

	return &mx
}
