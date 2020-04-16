// gomuks - A terminal Matrix client written in Go.
// Copyright (C) 2019 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package pushrules_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/events"
	"maunium.net/go/mautrix/pushrules"
)

var (
	blankTestRoom       pushrules.Room
	displaynameTestRoom pushrules.Room

	countConditionTestEvent *events.Event

	displaynamePushCondition *pushrules.PushCondition
)

func init() {
	blankTestRoom = newFakeRoom(1)

	countConditionTestEvent = &events.Event{
		Sender:    "@tulir:maunium.net",
		Type:      events.EventMessage,
		Timestamp: 1523791120,
		ID:        "$123:maunium.net",
		RoomID:    "!fakeroom:maunium.net",
		Content: events.Content{
			MsgType: events.MsgText,
			Body:    "test",
		},
	}

	displaynameTestRoom = newFakeRoom(4)
	displaynamePushCondition = &pushrules.PushCondition{
		Kind: pushrules.KindContainsDisplayName,
	}
}

func newFakeEvent(evtType events.Type, content events.Content) *events.Event {
	return &events.Event{
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

func TestPushCondition_Match_InvalidKind(t *testing.T) {
	condition := &pushrules.PushCondition{
		Kind: pushrules.PushCondKind("invalid"),
	}
	event := newFakeEvent(events.Type{Type: "m.room.foobar"}, events.Content{})
	assert.False(t, condition.Match(blankTestRoom, event))
}

type FakeRoom struct {
	members map[string]*events.Member
	owner   string
}

func newFakeRoom(memberCount int) *FakeRoom {
	room := &FakeRoom{
		owner:   "@tulir:maunium.net",
		members: make(map[string]*events.Member),
	}

	if memberCount >= 1 {
		room.members["@tulir:maunium.net"] = &events.Member{
			Membership:  events.MembershipJoin,
			Displayname: "tulir",
		}
	}

	for i := 0; i < memberCount-1; i++ {
		mxid := fmt.Sprintf("@extrauser_%d:matrix.org", i)
		room.members[mxid] = &events.Member{
			Membership:  events.MembershipJoin,
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
