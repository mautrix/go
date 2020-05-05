// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pushrules_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPushCondition_Match_KindMemberCount_OneToOne_ImplicitPrefix(t *testing.T) {
	condition := newCountPushCondition("2")
	room := newFakeRoom(2)
	assert.True(t, condition.Match(room, countConditionTestEvent))
}

func TestPushCondition_Match_KindMemberCount_OneToOne_ExplicitPrefix(t *testing.T) {
	condition := newCountPushCondition("==2")
	room := newFakeRoom(2)
	assert.True(t, condition.Match(room, countConditionTestEvent))
}

func TestPushCondition_Match_KindMemberCount_BigRoom(t *testing.T) {
	condition := newCountPushCondition(">200")
	room := newFakeRoom(201)
	assert.True(t, condition.Match(room, countConditionTestEvent))
}

func TestPushCondition_Match_KindMemberCount_BigRoom_Fail(t *testing.T) {
	condition := newCountPushCondition(">=200")
	room := newFakeRoom(199)
	assert.False(t, condition.Match(room, countConditionTestEvent))
}

func TestPushCondition_Match_KindMemberCount_SmallRoom(t *testing.T) {
	condition := newCountPushCondition("<10")
	room := newFakeRoom(9)
	assert.True(t, condition.Match(room, countConditionTestEvent))
}

func TestPushCondition_Match_KindMemberCount_SmallRoom_Fail(t *testing.T) {
	condition := newCountPushCondition("<=10")
	room := newFakeRoom(11)
	assert.False(t, condition.Match(room, countConditionTestEvent))
}

func TestPushCondition_Match_KindMemberCount_InvalidPrefix(t *testing.T) {
	condition := newCountPushCondition("??10")
	room := newFakeRoom(11)
	assert.False(t, condition.Match(room, countConditionTestEvent))
}

func TestPushCondition_Match_KindMemberCount_InvalidCondition(t *testing.T) {
	condition := newCountPushCondition("foobar")
	room := newFakeRoom(1)
	assert.False(t, condition.Match(room, countConditionTestEvent))
}
