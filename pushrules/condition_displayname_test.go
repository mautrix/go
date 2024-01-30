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

func TestPushCondition_Match_DisplayName(t *testing.T) {
	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    "tulir: test mention",
	})
	evt.Sender = "@someone_else:matrix.org"
	assert.True(t, displaynamePushCondition.Match(displaynameTestRoom, evt))
}

func TestPushCondition_Match_DisplayName_Fail(t *testing.T) {
	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    "not a mention",
	})
	evt.Sender = "@someone_else:matrix.org"
	assert.False(t, displaynamePushCondition.Match(displaynameTestRoom, evt))
}

func TestPushCondition_Match_DisplayName_FailsOnEmptyRoom(t *testing.T) {
	emptyRoom := newFakeRoom(0)
	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    "tulir: this room doesn't have the owner Member available, so it fails.",
	})
	evt.Sender = "@someone_else:matrix.org"
	assert.False(t, displaynamePushCondition.Match(emptyRoom, evt))
}
