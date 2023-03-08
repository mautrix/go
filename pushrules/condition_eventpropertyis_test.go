// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pushrules_test

import (
	"maunium.net/go/mautrix/event"

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
