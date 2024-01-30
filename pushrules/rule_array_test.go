// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pushrules_test

import (
	"github.com/stretchr/testify/assert"

	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/pushrules"

	"testing"
)

func TestPushRuleArray_GetActions_FirstMatchReturns(t *testing.T) {
	cond1 := newMatchPushCondition("content.msgtype", "m.emote")
	cond2 := newMatchPushCondition("content.body", "no match")
	actions1 := pushrules.PushActionArray{
		{Action: pushrules.ActionNotify},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: "ping"},
	}
	rule1 := &pushrules.PushRule{
		Type:       pushrules.OverrideRule,
		Enabled:    true,
		Conditions: []*pushrules.PushCondition{cond1, cond2},
		Actions:    actions1,
	}

	actions2 := pushrules.PushActionArray{
		{Action: pushrules.ActionDontNotify},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight, Value: false},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: "pong"},
	}
	rule2 := &pushrules.PushRule{
		Type:    pushrules.RoomRule,
		Enabled: true,
		RuleID:  "!fakeroom:maunium.net",
		Actions: actions2,
	}

	actions3 := pushrules.PushActionArray{
		{Action: pushrules.ActionCoalesce},
	}
	rule3 := &pushrules.PushRule{
		Type:    pushrules.SenderRule,
		Enabled: true,
		RuleID:  "@tulir:maunium.net",
		Actions: actions3,
	}

	rules := pushrules.PushRuleArray{rule1, rule2, rule3}

	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgEmote,
		Body:    "is testing pushrules",
	})
	assert.Equal(t, rules.GetActions(blankTestRoom, evt), actions2)
}

func TestPushRuleArray_GetActions_NoMatchesIsNil(t *testing.T) {
	cond1 := newMatchPushCondition("content.msgtype", "m.emote")
	cond2 := newMatchPushCondition("content.body", "no match")
	actions1 := pushrules.PushActionArray{
		{Action: pushrules.ActionNotify},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: "ping"},
	}
	rule1 := &pushrules.PushRule{
		Type:       pushrules.OverrideRule,
		Enabled:    true,
		Conditions: []*pushrules.PushCondition{cond1, cond2},
		Actions:    actions1,
	}

	actions2 := pushrules.PushActionArray{
		{Action: pushrules.ActionDontNotify},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight, Value: false},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: "pong"},
	}
	rule2 := &pushrules.PushRule{
		Type:    pushrules.RoomRule,
		Enabled: true,
		RuleID:  "!realroom:maunium.net",
		Actions: actions2,
	}

	actions3 := pushrules.PushActionArray{
		{Action: pushrules.ActionCoalesce},
	}
	rule3 := &pushrules.PushRule{
		Type:    pushrules.SenderRule,
		Enabled: true,
		RuleID:  "@otheruser:maunium.net",
		Actions: actions3,
	}

	rules := pushrules.PushRuleArray{rule1, rule2, rule3}

	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgEmote,
		Body:    "is testing pushrules",
	})
	assert.Nil(t, rules.GetActions(blankTestRoom, evt))
}

func TestPushRuleMap_GetActions_RoomRuleExists(t *testing.T) {
	actions1 := pushrules.PushActionArray{
		{Action: pushrules.ActionDontNotify},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight, Value: false},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: "pong"},
	}
	rule1 := &pushrules.PushRule{
		Type:    pushrules.RoomRule,
		Enabled: true,
		RuleID:  "!realroom:maunium.net",
		Actions: actions1,
	}

	actions2 := pushrules.PushActionArray{
		{Action: pushrules.ActionNotify},
	}
	rule2 := &pushrules.PushRule{
		Type:    pushrules.RoomRule,
		Enabled: true,
		RuleID:  "!thirdroom:maunium.net",
		Actions: actions2,
	}

	actions3 := pushrules.PushActionArray{
		{Action: pushrules.ActionCoalesce},
	}
	rule3 := &pushrules.PushRule{
		Type:    pushrules.RoomRule,
		Enabled: true,
		RuleID:  "!fakeroom:maunium.net",
		Actions: actions3,
	}

	rules := pushrules.PushRuleMap{
		Map: map[string]*pushrules.PushRule{
			rule1.RuleID: rule1,
			rule2.RuleID: rule2,
			rule3.RuleID: rule3,
		},
		Type: pushrules.RoomRule,
	}

	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgEmote,
		Body:    "is testing pushrules",
	})
	assert.Equal(t, rules.GetActions(blankTestRoom, evt), actions3)
}

func TestPushRuleMap_GetActions_RoomRuleDoesntExist(t *testing.T) {
	actions1 := pushrules.PushActionArray{
		{Action: pushrules.ActionDontNotify},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight, Value: false},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: "pong"},
	}
	rule1 := &pushrules.PushRule{
		Type:    pushrules.RoomRule,
		Enabled: true,
		RuleID:  "!realroom:maunium.net",
		Actions: actions1,
	}

	actions2 := pushrules.PushActionArray{
		{Action: pushrules.ActionNotify},
	}
	rule2 := &pushrules.PushRule{
		Type:    pushrules.RoomRule,
		Enabled: true,
		RuleID:  "!thirdroom:maunium.net",
		Actions: actions2,
	}

	rules := pushrules.PushRuleMap{
		Map: map[string]*pushrules.PushRule{
			rule1.RuleID: rule1,
			rule2.RuleID: rule2,
		},
		Type: pushrules.RoomRule,
	}

	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgEmote,
		Body:    "is testing pushrules",
	})
	assert.Nil(t, rules.GetActions(blankTestRoom, evt))
}

func TestPushRuleMap_GetActions_SenderRuleExists(t *testing.T) {
	actions1 := pushrules.PushActionArray{
		{Action: pushrules.ActionDontNotify},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight, Value: false},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: "pong"},
	}
	rule1 := &pushrules.PushRule{
		Type:    pushrules.SenderRule,
		Enabled: true,
		RuleID:  "@tulir:maunium.net",
		Actions: actions1,
	}

	actions2 := pushrules.PushActionArray{
		{Action: pushrules.ActionNotify},
	}
	rule2 := &pushrules.PushRule{
		Type:    pushrules.SenderRule,
		Enabled: true,
		RuleID:  "@someone:maunium.net",
		Actions: actions2,
	}

	actions3 := pushrules.PushActionArray{
		{Action: pushrules.ActionCoalesce},
	}
	rule3 := &pushrules.PushRule{
		Type:    pushrules.SenderRule,
		Enabled: true,
		RuleID:  "@otheruser:matrix.org",
		Actions: actions3,
	}

	rules := pushrules.PushRuleMap{
		Map: map[string]*pushrules.PushRule{
			rule1.RuleID: rule1,
			rule2.RuleID: rule2,
			rule3.RuleID: rule3,
		},
		Type: pushrules.SenderRule,
	}

	evt := newFakeEvent(event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgEmote,
		Body:    "is testing pushrules",
	})
	assert.Equal(t, rules.GetActions(blankTestRoom, evt), actions1)
}

func TestPushRuleArray_SetTypeAndMap(t *testing.T) {
	actions1 := pushrules.PushActionArray{
		{Action: pushrules.ActionDontNotify},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakHighlight, Value: false},
		{Action: pushrules.ActionSetTweak, Tweak: pushrules.TweakSound, Value: "pong"},
	}
	rule1 := &pushrules.PushRule{
		Enabled: true,
		RuleID:  "@tulir:maunium.net",
		Actions: actions1,
	}

	actions2 := pushrules.PushActionArray{
		{Action: pushrules.ActionNotify},
	}
	rule2 := &pushrules.PushRule{
		Enabled: true,
		RuleID:  "@someone:maunium.net",
		Actions: actions2,
	}

	actions3 := pushrules.PushActionArray{
		{Action: pushrules.ActionCoalesce},
	}
	rule3 := &pushrules.PushRule{
		Enabled: true,
		RuleID:  "@otheruser:matrix.org",
		Actions: actions3,
	}

	ruleArray := pushrules.PushRuleArray{rule1, rule2, rule3}
	ruleMap := ruleArray.SetTypeAndMap(pushrules.SenderRule)
	assert.Equal(t, pushrules.SenderRule, ruleMap.Type)
	for _, rule := range ruleArray {
		assert.Equal(t, rule, ruleMap.Map[rule.RuleID])
	}
	newRuleArray := ruleMap.Unmap()
	for _, rule := range ruleArray {
		assert.Contains(t, newRuleArray, rule)
	}
}
