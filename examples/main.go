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

package main

import (
	"flag"
	"fmt"

	"maunium.net/go/mautrix"
)

var homeserver = flag.String("homeserver", "https://matrix.org", "Matrix homeserver")
var username = flag.String("username", "", "Matrix username localpart")
var password = flag.String("password", "", "Matrix password")

func main() {
	session := mautrix.Create(*homeserver)

	err := session.PasswordLogin(*username, *password)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Login successful")

	go session.Listen()

	for {
		select {
		case evt := <-session.Timeline:
			switch evt.Type {
			case mautrix.EvtRoomMessage:
				fmt.Printf("<%[1]s> %[4]s (%[2]s/%[3]s)\n", evt.Sender, evt.Type, evt.ID, evt.Content["body"])
			default:
				fmt.Println(evt.Type)
			}
		case roomID := <-session.InviteChan:
			invite := session.Invites[roomID]
			fmt.Printf("%s invited me to %s (%s)\n", invite.Sender, invite.Name, invite.ID)
			fmt.Println(invite.Accept())
		}
	}
}
