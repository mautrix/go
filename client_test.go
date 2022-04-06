package mautrix

import (
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"net/url"
	"testing"
)

func TestBuildURL(t *testing.T) {
	baseUrl, _ := url.Parse("subdomain.example.com")
	cli := Client{
		HomeserverURL:    baseUrl,
		AppServiceUserID: id.UserID("@_user_sms_2296:example.com"),
		Prefix:           URLPath{"_matrix", "client", "r0"},
	}
	urlPath := cli.BuildURL(
		"rooms",
		id.RoomID("!HJFqYPQsomcCFfIYBC:example.com"),
		"state",
		event.StateBridge.String(),
		"fi.mau.imessage://sms/SMS;-;3340",
	)
	assertEqual(
		t,
		"https://subdomain.example.com/_matrix/client/r0/rooms/%21HJFqYPQsomcCFfIYBC:example.com/state/m.bridge/fi.mau.imessage:%2F%2Fsms%2FSMS%3B-%3B3340?user_id=%40_user_sms_2296%3Aexample.com",
		urlPath,
	)
}

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Fatalf("%s != %s", a, b)
	}
}
