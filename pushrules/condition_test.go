// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pushrules_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
	"github.com/element-hq/mautrix-go/pushrules"
)

var (
	blankTestRoom       pushrules.Room
	displaynameTestRoom pushrules.Room

	countConditionTestEvent *event.Event

	displaynamePushCondition *pushrules.PushCondition
)

func init() {
	blankTestRoom = newFakeRoom(1)

	countConditionTestEvent = &event.Event{
		Sender:    "@tulir:maunium.net",
		Type:      event.EventMessage,
		Timestamp: 1523791120,
		ID:        "$123:maunium.net",
		RoomID:    "!fakeroom:maunium.net",
		Content: event.Content{
			Raw: map[string]interface{}{
				"msgtype": "m.text",
				"body":    "test",
			},
			Parsed: &event.MessageEventContent{
				MsgType: event.MsgText,
				Body:    "test",
			},
		},
	}

	displaynameTestRoom = newFakeRoom(4)
	displaynamePushCondition = &pushrules.PushCondition{
		Kind: pushrules.KindContainsDisplayName,
	}
}

func newFakeEvent(evtType event.Type, parsed interface{}) *event.Event {
	data, err := json.Marshal(parsed)
	if err != nil {
		panic(err)
	}
	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	if err != nil {
		panic(err)
	}
	content := event.Content{
		VeryRaw: data,
		Raw:     raw,
		Parsed:  parsed,
	}
	return &event.Event{
		Sender:    "@tulir:maunium.net",
		Type:      evtType,
		Timestamp: 1523791120,
		ID:        "$123:maunium.net",
		RoomID:    "!fakeroom:maunium.net",
		Content:   content,
	}
}

func newCountPushCondition(condition string) *pushrules.PushCondition {
	return &pushrules.PushCondition{
		Kind:                 pushrules.KindRoomMemberCount,
		MemberCountCondition: condition,
	}
}

func newMatchPushCondition(key, pattern string) *pushrules.PushCondition {
	return &pushrules.PushCondition{
		Kind:    pushrules.KindEventMatch,
		Key:     key,
		Pattern: pattern,
	}
}

func newEventPropertyIsPushCondition(key string, value any) *pushrules.PushCondition {
	return &pushrules.PushCondition{
		Kind:  pushrules.KindEventPropertyIs,
		Key:   key,
		Value: value,
	}
}

func newEventPropertyContainsPushCondition(key string, value any) *pushrules.PushCondition {
	return &pushrules.PushCondition{
		Kind:  pushrules.KindEventPropertyContains,
		Key:   key,
		Value: value,
	}
}

func TestPushCondition_Match_InvalidKind(t *testing.T) {
	condition := &pushrules.PushCondition{
		Kind: pushrules.PushCondKind("invalid"),
	}
	evt := newFakeEvent(event.Type{Type: "m.room.foobar"}, &struct{}{})
	assert.False(t, condition.Match(blankTestRoom, evt))
}

type FakeRoom struct {
	members map[string]*event.MemberEventContent
	owner   string

	events map[id.EventID]*event.Event
}

func newFakeRoom(memberCount int) *FakeRoom {
	room := &FakeRoom{
		owner:   "@tulir:maunium.net",
		members: make(map[string]*event.MemberEventContent),
		events:  make(map[id.EventID]*event.Event),
	}

	if memberCount >= 1 {
		room.members["@tulir:maunium.net"] = &event.MemberEventContent{
			Membership:  event.MembershipJoin,
			Displayname: "tulir",
		}
	}

	for i := 0; i < memberCount-1; i++ {
		mxid := fmt.Sprintf("@extrauser_%d:matrix.org", i)
		room.members[mxid] = &event.MemberEventContent{
			Membership:  event.MembershipJoin,
			Displayname: fmt.Sprintf("Extra User %d", i),
		}
	}

	return room
}

func (fr *FakeRoom) GetMemberCount() int {
	return len(fr.members)
}

func (fr *FakeRoom) GetOwnDisplayname() string {
	member, ok := fr.members[fr.owner]
	if ok {
		return member.Displayname
	}
	return ""
}

func (fr *FakeRoom) GetEvent(evtID id.EventID) *event.Event {
	return fr.events[evtID]
}
