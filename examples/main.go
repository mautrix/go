package main

import (
	"fmt"
	"maunium.net/go/mautrix"
)

func main() {
	session := mautrix.Create("https://matrix.org")

	err := session.PasswordLogin("username", "password")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Login successful")

	go session.Listen()

	go func() {
		for roomID := range session.InviteChan {
			invite := session.Invites[roomID]
			fmt.Printf("%s invited me to %s (%s)\n", invite.Sender, invite.Name, invite.ID)
			fmt.Println(invite.Accept())
		}
	}()

	for evt := range session.Timeline {
		switch evt.Type {
		case mautrix.EvtRoomMessage:
			fmt.Printf("<%[1]s> %[4]s (%[2]s/%[3]s)\n", evt.Sender, evt.Type, evt.ID, evt.Content["body"])
		default:
			fmt.Println(evt.Type)
		}
	}
}
