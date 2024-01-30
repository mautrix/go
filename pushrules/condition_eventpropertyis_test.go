// Copyright (c) 2023 Tulir Asokan
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

func TestPushCondition_Match_KindEventPropertyIs_MsgType(t *testing.T) {
	condition := newEventPropertyIsPushCondition("content.msgtype", "m.emote")
	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgEmote,
		Body:    "tests gomuks pushconditions",
	})
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEventPropertyIs_MsgType_Fail(t *testing.T) {
	condition := newEventPropertyIsPushCondition("content.msgtype", "m.emote")

	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    "I'm testing gomuks pushconditions",
	})
	assert.False(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEventPropertyIs_Integer(t *testing.T) {
	condition := newEventPropertyIsPushCondition("content.meow", 5)
	evt := newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": 5})
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEventPropertyIs_Integer_NoMatch(t *testing.T) {
	condition := newEventPropertyIsPushCondition("content.meow", 0)
	evt := newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": "NaN"})
	assert.False(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEventPropertyIs_String(t *testing.T) {
	condition := newEventPropertyIsPushCondition("content.meow", "foo")
	evt := newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": "foo"})
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEventPropertyIs_String_NoMatch(t *testing.T) {
	condition := newEventPropertyIsPushCondition("content.meow", "foo")
	evt := newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": "foo!"})
	assert.False(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEventPropertyIs_Null(t *testing.T) {
	condition := newEventPropertyIsPushCondition("content.meow", nil)
	evt := newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": nil})
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEventPropertyIs_Null_NoMatch(t *testing.T) {
	condition := newEventPropertyIsPushCondition("content.meow", nil)
	evt := newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": "a"})
	assert.False(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEventPropertyIs_Bool(t *testing.T) {
	condition := newEventPropertyIsPushCondition("content.meow", false)
	evt := newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": false})
	assert.True(t, condition.Match(blankTestRoom, evt))
	condition = newEventPropertyIsPushCondition("content.meow", true)
	evt = newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": true})
	assert.True(t, condition.Match(blankTestRoom, evt))
}

func TestPushCondition_Match_KindEventPropertyIs_Bool_NoMatch(t *testing.T) {
	condition := newEventPropertyIsPushCondition("content.meow", false)
	evt := newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": true})
	assert.False(t, condition.Match(blankTestRoom, evt))
	condition = newEventPropertyIsPushCondition("content.meow", true)
	evt = newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": false})
	assert.False(t, condition.Match(blankTestRoom, evt))
	condition = newEventPropertyIsPushCondition("content.meow", false)
	evt = newFakeEvent(event.NewEventType("m.room.foo"), map[string]any{"meow": ""})
	assert.False(t, condition.Match(blankTestRoom, evt))
}
