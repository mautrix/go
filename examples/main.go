package main

import (
	"fmt"
	"log"

	"github.com/geir54/goMatrix"
)

func main() {
	session := goMatrix.Init("https://matrix.org")

	err := session.Login("username", "password")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Login successful")

	session.Start()

	for {
		select {
		case msg := <-session.OnNewMsg:
			fmt.Println(msg)
		default:
		}
	}

}
