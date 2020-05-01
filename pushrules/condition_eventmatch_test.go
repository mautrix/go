// gomuks - A terminal Matrix client written in Go.
// Copyright (C) 2020 Tulir Asokan
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
	"maunium.net/go/mautrix/event"

	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPushCondition_Match_KindEvent_MsgType(t *testing.T) {
	condition := newMatchPushCondition("content.msgtype", "m.emote")
	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgEmote,
		Body: "tests gomuks pushconditions",
	})
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_MsgType_Fail(t *testing.T) {
	condition := newMatchPushCondition("content.msgtype", "m.emote")

	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgText,
		Body: "I'm testing gomuks pushconditions",
	})
	assert.False(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_EventType(t *testing.T) {
	condition := newMatchPushCondition("type", "m.room.foo")
	evt := newFakeEvent(event.NewEventType("m.room.foo"), &struct{}{})
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_EventType_IllegalGlob(t *testing.T) {
	condition := newMatchPushCondition("type", "m.room.invalid_glo[b")
	evt := newFakeEvent(event.NewEventType("m.room.invalid_glob"), &struct{}{})
	assert.False(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_Sender_Fail(t *testing.T) {
	condition := newMatchPushCondition("sender", "@foo:maunium.net")
	evt := newFakeEvent(event.NewEventType("m.room.foo"), &struct{}{})
	assert.False(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_RoomID(t *testing.T) {
	condition := newMatchPushCondition("room_id", "!fakeroom:maunium.net")
	evt := newFakeEvent(event.NewEventType(""), &struct{}{})
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_BlankStateKey(t *testing.T) {
	condition := newMatchPushCondition("state_key", "")
	evt := newFakeEvent(event.NewEventType("m.room.foo"), &struct{}{})
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_BlankStateKey_Fail(t *testing.T) {
	condition := newMatchPushCondition("state_key", "not blank")
	evt := newFakeEvent(event.NewEventType("m.room.foo"), &struct{}{})
	assert.False(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_NonBlankStateKey(t *testing.T) {
	condition := newMatchPushCondition("state_key", "*:maunium.net")
	evt := newFakeEvent(event.NewEventType("m.room.foo"), &struct{}{})
	evt.StateKey = (*string)(&evt.Sender)
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_UnknownKey(t *testing.T) {
	condition := newMatchPushCondition("non-existent key", "doesn't affect anything")
	evt := newFakeEvent(event.NewEventType("m.room.foo"), &struct{}{})
	assert.False(t, condition.Match(blankTestRoom, evt))
}
