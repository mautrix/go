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
