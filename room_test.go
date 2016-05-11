package goMatrix

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoomNameToID(t *testing.T) {
	session := Init("test")
	session.Rooms["!asdfasdf:matrix.org"] = RoomInfo{Name: "SomeRoomName"}
	session.Rooms["!asdf1asdf:matrix.org"] = RoomInfo{Name: "SomeRoomName1"}

	if session.RoomNameToID("SomeRoomName") != "!asdfasdf:matrix.org" {
		t.Errorf("Did not find correct room ")
	}
}

func TestSendToRoom(t *testing.T) {
	testMsg := "This is a test! It's testing messages \" :)"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var data map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			t.Errorf("JSON decoder retured error: " + err.Error())
		}

		if data["body"] != testMsg {
			t.Errorf("Did not get the expected message")
		}

		json := `{"event_id":"$146291282519476fpZcj:matrix.org"}`
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, json)
	}))
	defer ts.Close()

	session := Init(ts.URL)
	session.SendToRoom("!cURbafjkfsMDVwdRDQ:matrix.org", testMsg)

}
