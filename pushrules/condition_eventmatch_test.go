// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pushrules_test

import (
	"github.com/element-hq/mautrix-go/event"

	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPushCondition_Match_KindEvent_MsgType(t *testing.T) {
	condition := newMatchPushCondition("content.msgtype", "m.emote")
	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgEmote,
		Body:    "tests gomuks pushconditions",
	})
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_MsgType_Fail(t *testing.T) {
	condition := newMatchPushCondition("content.msgtype", "m.emote")

	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    "I'm testing gomuks pushconditions",
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
	blankString := ""
	evt.StateKey = &blankString
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEvent_NonStateStateKey(t *testing.T) {
	condition := newMatchPushCondition("state_key", "")
	evt := newFakeEvent(event.NewEventType("m.room.foo"), &struct{}{})
	assert.False(t, condition.Match(blankTestRoom, evt))
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
