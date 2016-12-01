package gomatrix

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
)

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

func TestClient_LeaveRoom(t *testing.T) {
	cli := mockClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == "POST" && req.URL.Path == "/_matrix/client/r0/rooms/!foo:bar/leave" {
			return &http.Response{
				StatusCode: 200,
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
			}, nil
		}
		return nil, fmt.Errorf("unhandled URL: %s", req.URL.Path)
	})

	if _, err := cli.LeaveRoom("!foo:bar"); err != nil {
		t.Fatalf("LeaveRoom: error, got %s", err.Error())
	}
}

func mockClient(fn func(*http.Request) (*http.Response, error)) *Client {
	mrt := MockRoundTripper{
		RT: fn,
	}

	cli, _ := NewClient("https://test.gomatrix.org", "@user:test.gomatrix.org", "abcdef")
	cli.Client = &http.Client{
		Transport: mrt,
	}
	return cli
}

type MockRoundTripper struct {
	RT func(*http.Request) (*http.Response, error)
}

func (t MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.RT(req)
}
