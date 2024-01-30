// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pushrules_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/element-hq/mautrix-go/pushrules"
)

func TestPushActionArray_Should_EmptyArrayReturnsDefaults(t *testing.T) {
	should := pushrules.PushActionArray{}.Should()
	assert.False(t, should.NotifySpecified)
	assert.False(t, should.Notify)
	assert.False(t, should.Highlight)
	assert.False(t, should.PlaySound)
	assert.Empty(t, should.SoundName)
}

func TestPushActionArray_Should_MixedArrayReturnsExpected1(t *testing.T) {
	should := pushrules.PushActionArray{
		{Action: pushrules.ActionNotify},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: "ping"},
	}.Should()
	assert.True(t, should.NotifySpecified)
	assert.True(t, should.Notify)
	assert.True(t, should.Highlight)
	assert.True(t, should.PlaySound)
	assert.Equal(t, "ping", should.SoundName)
}

func TestPushActionArray_Should_MixedArrayReturnsExpected2(t *testing.T) {
	should := pushrules.PushActionArray{
		{Action: pushrules.ActionDontNotify},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight, Value: false},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: ""},
	}.Should()
	assert.True(t, should.NotifySpecified)
	assert.False(t, should.Notify)
	assert.False(t, should.Highlight)
	assert.False(t, should.PlaySound)
	assert.Empty(t, should.SoundName)
}

func TestPushActionArray_Should_NotifySet(t *testing.T) {
	should := pushrules.PushActionArray{
		{Action: pushrules.ActionNotify},
	}.Should()
	assert.True(t, should.NotifySpecified)
	assert.True(t, should.Notify)
	assert.False(t, should.Highlight)
	assert.False(t, should.PlaySound)
	assert.Empty(t, should.SoundName)
}

func TestPushActionArray_Should_NotifyAndCoalesceDoTheSameThing(t *testing.T) {
	should1 := pushrules.PushActionArray{
		{Action: pushrules.ActionNotify},
	}.Should()
	should2 := pushrules.PushActionArray{
		{Action: pushrules.ActionCoalesce},
	}.Should()
	assert.Equal(t, should1, should2)
}

func TestPushActionArray_Should_DontNotify(t *testing.T) {
	should := pushrules.PushActionArray{
		{Action: pushrules.ActionDontNotify},
	}.Should()
	assert.True(t, should.NotifySpecified)
	assert.False(t, should.Notify)
	assert.False(t, should.Highlight)
	assert.False(t, should.PlaySound)
	assert.Empty(t, should.SoundName)
}

func TestPushActionArray_Should_HighlightBlank(t *testing.T) {
	should := pushrules.PushActionArray{
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight},
	}.Should()
	assert.False(t, should.NotifySpecified)
	assert.False(t, should.Notify)
	assert.True(t, should.Highlight)
	assert.False(t, should.PlaySound)
	assert.Empty(t, should.SoundName)
}

func TestPushActionArray_Should_HighlightFalse(t *testing.T) {
	should := pushrules.PushActionArray{
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight, Value: false},
	}.Should()
	assert.False(t, should.NotifySpecified)
	assert.False(t, should.Notify)
	assert.False(t, should.Highlight)
	assert.False(t, should.PlaySound)
	assert.Empty(t, should.SoundName)
}

func TestPushActionArray_Should_SoundName(t *testing.T) {
	should := pushrules.PushActionArray{
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: "ping"},
	}.Should()
	assert.False(t, should.NotifySpecified)
	assert.False(t, should.Notify)
	assert.False(t, should.Highlight)
	assert.True(t, should.PlaySound)
	assert.Equal(t, "ping", should.SoundName)
}

func TestPushActionArray_Should_SoundNameEmpty(t *testing.T) {
	should := pushrules.PushActionArray{
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: ""},
	}.Should()
	assert.False(t, should.NotifySpecified)
	assert.False(t, should.Notify)
	assert.False(t, should.Highlight)
	assert.False(t, should.PlaySound)
	assert.Empty(t, should.SoundName)
}

func TestPushAction_UnmarshalJSON_InvalidJSONFails(t *testing.T) {
	pa := &pushrules.PushAction{}
	err := pa.UnmarshalJSON([]byte("Not JSON"))
	assert.NotNil(t, err)
}

func TestPushAction_UnmarshalJSON_InvalidTypeDoesNothing(t *testing.T) {
	pa := &pushrules.PushAction{
		Action: pushrules.PushActionType("unchanged"),
		Tweak:  pushrules.PushActionTweak("unchanged"),
		Value:  "unchanged",
	}

	err := pa.UnmarshalJSON([]byte(`{"foo": "bar"}`))
	assert.Nil(t, err)
	err = pa.UnmarshalJSON([]byte(`9001`))
	assert.Nil(t, err)

	assert.Equal(t, pushrules.PushActionType("unchanged"), pa.Action)
	assert.Equal(t, pushrules.PushActionTweak("unchanged"), pa.Tweak)
	assert.Equal(t, "unchanged", pa.Value)
}

func TestPushAction_UnmarshalJSON_StringChangesActionType(t *testing.T) {
	pa := &pushrules.PushAction{
		Action: pushrules.PushActionType("unchanged"),
		Tweak:  pushrules.PushActionTweak("unchanged"),
		Value:  "unchanged",
	}

	err := pa.UnmarshalJSON([]byte(`"foo"`))
	assert.Nil(t, err)

	assert.Equal(t, pushrules.PushActionType("foo"), pa.Action)
	assert.Equal(t, pushrules.PushActionTweak("unchanged"), pa.Tweak)
	assert.Equal(t, "unchanged", pa.Value)
}

func TestPushAction_UnmarshalJSON_SetTweakChangesTweak(t *testing.T) {
	pa := &pushrules.PushAction{
		Action: pushrules.PushActionType("unchanged"),
		Tweak:  pushrules.PushActionTweak("unchanged"),
		Value:  "unchanged",
	}

	err := pa.UnmarshalJSON([]byte(`{"set_tweak": "foo", "value": 123.0}`))
	assert.Nil(t, err)

	assert.Equal(t, pushrules.ActionSetTweak, pa.Action)
	assert.Equal(t, pushrules.PushActionTweak("foo"), pa.Tweak)
	assert.Equal(t, 123.0, pa.Value)
}

func TestPushAction_MarshalJSON_TweakOutputWorks(t *testing.T) {
	pa := &pushrules.PushAction{
		Action: pushrules.ActionSetTweak,
		Tweak:  pushrules.PushActionTweak("foo"),
		Value:  "bar",
	}
	data, err := pa.MarshalJSON()
	assert.Nil(t, err)
	assert.Equal(t, []byte(`{"set_tweak":"foo","value":"bar"}`), data)
}

func TestPushAction_MarshalJSON_OtherOutputWorks(t *testing.T) {
	pa := &pushrules.PushAction{
		Action: pushrules.PushActionType("something else"),
		Tweak:  pushrules.PushActionTweak("foo"),
		Value:  "bar",
	}
	data, err := pa.MarshalJSON()
	assert.Nil(t, err)
	assert.Equal(t, []byte(`"something else"`), data)
}
