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

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/pushrules"
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
			MsgType: event.MsgText,
			Body:    "test",
		},
	}

	displaynameTestRoom = newFakeRoom(4)
	displaynamePushCondition = &pushrules.PushCondition{
		Kind: pushrules.KindContainsDisplayName,
	}
}

func newFakeEvent(evtType event.Type, content event.Content) *event.Event {
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

func TestPushCondition_Match_InvalidKind(t *testing.T) {
	condition := &pushrules.PushCondition{
		Kind: pushrules.PushCondKind("invalid"),
	}
	evt := newFakeEvent(event.Type{Type: "m.room.foobar"}, event.Content{})
	assert.False(t, condition.Match(blankTestRoom, evt))
}

type FakeRoom struct {
	members map[string]*event.Member
	owner   string
}

func newFakeRoom(memberCount int) *FakeRoom {
	room := &FakeRoom{
		owner:   "@tulir:maunium.net",
		members: make(map[string]*event.Member),
	}

	if memberCount >= 1 {
		room.members["@tulir:maunium.net"] = &event.Member{
			Membership:  event.MembershipJoin,
			Displayname: "tulir",
		}
	}

	for i := 0; i < memberCount-1; i++ {
		mxid := fmt.Sprintf("@extrauser_%d:matrix.org", i)
		room.members[mxid] = &event.Member{
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
