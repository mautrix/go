package goMatrix

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSync(t *testing.T) {
	json := `{"next_batch":"s20485139_5595669_21807_1482044_6200_1620","account_data":{"events":[]}, "rooms":{"leave":{},"join":{"!cURbafjkfsMDVwdRDQ:matrix.org":{"unread_notifications":{"highlight_count":0,"notification_count":0},"timeline":{"limited":false,"prev_batch":"s20485117_5595574_21805_1482043_6200_1620","events":[]},"state":{"events":[]},"ephemeral":{"events":[]},"account_data":{"events":[]}},"!dCUMzIpEGxMrXOnTSv:matrix.org":{"unread_notifications":{"highlight_count":0,"notification_count":0},"timeline":{"limited":false,"prev_batch":"s20485136_5595669_21807_1482044_6200_1620","events":[{"origin_server_ts":1462889279378,"sender":"@someone:matrix.org","event_id":"$1462879289110129etwWh:matrix.org","unsigned":{"age":4874},"content":{"body":"test","msgtype":"m.text"},"type":"m.room.message"}]},"state":{"events":[]},"ephemeral":{"events":[]},"account_data":{"events":[]}}},"invite":{}},"presence":{"events":[]}}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, json)
	}))
	defer ts.Close()

	session := Init(ts.URL)
	err := session.Sync()
	if err != nil {
		t.Error("Sync() returned error: " + err.Error())
	}

	msg := <-session.OnNewMsg
	if msg.Text != "test" {
		t.Error("Wrong text recived")
	}

	if msg.Sender != "@someone:matrix.org" {
		t.Error("Wrong sender")
	}

}
