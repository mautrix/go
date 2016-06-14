package main

import (
	"fmt"
	"maunium.net/go/mautrix"
)

func main() {
	session := mautrix.Init("https://matrix.org")

	err := session.Login("username", "password")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Login successful")

	session.Start()

	for {
		select {
		case msg := <-session.OnNewMsg:
			fmt.Printf("%s - %s - %s\n", msg.RoomName, msg.Sender, msg.Text)
		default:
		}
	}

}
