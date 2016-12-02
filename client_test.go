package gomatrix

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
)

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

func TestClient_StateEvent(t *testing.T) {
	cli := mockClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == "GET" && req.URL.Path == "/_matrix/client/r0/rooms/!foo:bar/state/m.room.name" {
			return &http.Response{
				StatusCode: 200,
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{"name":"Room Name Goes Here"}`)),
			}, nil
		}
		return nil, fmt.Errorf("unhandled URL: %s", req.URL.Path)
	})

	content := struct {
		Name string `json:"name"`
	}{}

	if err := cli.StateEvent("!foo:bar", "m.room.name", "", &content); err != nil {
		t.Fatalf("StateEvent: error, got %s", err.Error())
	}
	if content.Name != "Room Name Goes Here" {
		t.Fatalf("StateEvent: got %s, want %s", content.Name, "Room Name Goes Here")
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
