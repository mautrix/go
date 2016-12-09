package gomatrix

import "fmt"

func ExampleClient_BuildURLWithQuery() {
	cli, _ := NewClient("https://matrix.org", "@example:matrix.org", "abcdef123456")
	out := cli.BuildURLWithQuery([]string{"sync"}, map[string]string{
		"filter_id": "5",
	})
	fmt.Println(out)
	// Output: https://matrix.org/_matrix/client/r0/sync?access_token=abcdef123456&filter_id=5
}

func ExampleClient_BuildURL() {
	userID := "@example:matrix.org"
	cli, _ := NewClient("https://matrix.org", userID, "abcdef123456")
	out := cli.BuildURL("user", userID, "filter")
	fmt.Println(out)
	// Output: https://matrix.org/_matrix/client/r0/user/@example:matrix.org/filter?access_token=abcdef123456
}

func ExampleClient_BuildBaseURL() {
	userID := "@example:matrix.org"
	cli, _ := NewClient("https://matrix.org", userID, "abcdef123456")
	out := cli.BuildBaseURL("_matrix", "client", "r0", "directory", "room", "#matrix:matrix.org")
	fmt.Println(out)
	// Output: https://matrix.org/_matrix/client/r0/directory/room/%23matrix:matrix.org?access_token=abcdef123456
}

// Retrieve the content of a m.room.name state event.
func ExampleClient_StateEvent() {
	content := struct {
		name string `json:"name"`
	}{}
	cli, _ := NewClient("https://matrix.org", "@example:matrix.org", "abcdef123456")
	if err := cli.StateEvent("!foo:bar", "m.room.name", "", &content); err != nil {
		panic(err)
	}
}

// Join a room by ID.
func ExampleClient_JoinRoom_id() {
	cli, _ := NewClient("http://localhost:8008", "@example:localhost", "abcdef123456")
	if _, err := cli.JoinRoom("!uOILRrqxnsYgQdUzar:localhost", "", nil); err != nil {
		panic(err)
	}
}

// Join a room by alias.
func ExampleClient_JoinRoom_alias() {
	cli, _ := NewClient("http://localhost:8008", "@example:localhost", "abcdef123456")
	if resp, err := cli.JoinRoom("#test:localhost", "", nil); err != nil {
		panic(err)
	} else {
		// Use room ID for something.
		_ = resp.RoomID
	}
}

// Login to a local homeserver. This will set Client.UserID and Client.AccessToken on success.
func ExampleClient_Login() {
	cli, _ := NewClient("http://localhost:8008", "", "")
	_, err := cli.Login(&ReqLogin{
		Type:     "m.login.password",
		User:     "alice",
		Password: "wonderland",
	}, true)
	if err != nil {
		panic(err)
	}
}
