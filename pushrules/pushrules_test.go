// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pushrules_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/pushrules"
)

func TestEventToPushRules(t *testing.T) {
	evt := &event.Event{
		Type:      event.AccountDataPushRules,
		Timestamp: 1523380910,
		Content: event.Content{
			VeryRaw: json.RawMessage(JSONExamplePushRules),
		},
	}
	pushRuleset, err := pushrules.EventToPushRules(evt)
	assert.Nil(t, err)
	assert.NotNil(t, pushRuleset)

	assert.IsType(t, pushRuleset.Override, pushrules.PushRuleArray{})
	assert.IsType(t, pushRuleset.Content, pushrules.PushRuleArray{})
	assert.IsType(t, pushRuleset.Room, pushrules.PushRuleMap{})
	assert.IsType(t, pushRuleset.Sender, pushrules.PushRuleMap{})
	assert.IsType(t, pushRuleset.Underride, pushrules.PushRuleArray{})
	assert.Len(t, pushRuleset.Override, 2)
	assert.Len(t, pushRuleset.Content, 1)
	assert.Empty(t, pushRuleset.Room.Map)
	assert.Empty(t, pushRuleset.Sender.Map)
	assert.Len(t, pushRuleset.Underride, 6)

	assert.Len(t, pushRuleset.Content[0].Actions, 3)
	assert.True(t, pushRuleset.Content[0].Default)
	assert.True(t, pushRuleset.Content[0].Enabled)
	assert.Empty(t, pushRuleset.Content[0].Conditions)
	assert.Equal(t, "alice", pushRuleset.Content[0].Pattern)
	assert.Equal(t, ".m.rule.contains_user_name", pushRuleset.Content[0].RuleID)

	assert.False(t, pushRuleset.Override[0].Actions.Should().Notify)
	assert.True(t, pushRuleset.Override[0].Actions.Should().NotifySpecified)
}

const JSONExamplePushRules = `{
  "global": {
    "content": [
      {
        "actions": [
          "notify",
          {
            "set_tweak": "sound",
            "value": "default"
          },
          {
            "set_tweak": "highlight"
          }
        ],
        "default": true,
        "enabled": true,
        "pattern": "alice",
        "rule_id": ".m.rule.contains_user_name"
      }
    ],
    "override": [
      {
        "actions": [
          "dont_notify"
        ],
        "conditions": [],
        "default": true,
        "enabled": false,
        "rule_id": ".m.rule.master"
      },
      {
        "actions": [
          "dont_notify"
        ],
        "conditions": [
          {
            "key": "content.msgtype",
            "kind": "event_match",
            "pattern": "m.notice"
          }
        ],
        "default": true,
        "enabled": true,
        "rule_id": ".m.rule.suppress_notices"
      }
    ],
    "room": [],
    "sender": [],
    "underride": [
      {
        "actions": [
          "notify",
          {
            "set_tweak": "sound",
            "value": "ring"
          },
          {
            "set_tweak": "highlight",
            "value": false
          }
        ],
        "conditions": [
          {
            "key": "type",
            "kind": "event_match",
            "pattern": "m.call.invite"
          }
        ],
        "default": true,
        "enabled": true,
        "rule_id": ".m.rule.call"
      },
      {
        "actions": [
          "notify",
          {
            "set_tweak": "sound",
            "value": "default"
          },
          {
            "set_tweak": "highlight"
          }
        ],
        "conditions": [
          {
            "kind": "contains_display_name"
          }
        ],
        "default": true,
        "enabled": true,
        "rule_id": ".m.rule.contains_display_name"
      },
      {
        "actions": [
          "notify",
          {
            "set_tweak": "sound",
            "value": "default"
          },
          {
            "set_tweak": "highlight",
            "value": false
          }
        ],
        "conditions": [
          {
            "is": "2",
            "kind": "room_member_count"
          }
        ],
        "default": true,
        "enabled": true,
        "rule_id": ".m.rule.room_one_to_one"
      },
      {
        "actions": [
          "notify",
          {
            "set_tweak": "sound",
            "value": "default"
          },
          {
            "set_tweak": "highlight",
            "value": false
          }
        ],
        "conditions": [
          {
            "key": "type",
            "kind": "event_match",
            "pattern": "m.room.member"
          },
          {
            "key": "content.membership",
            "kind": "event_match",
            "pattern": "invite"
          },
          {
            "key": "state_key",
            "kind": "event_match",
            "pattern": "@alice:example.com"
          }
        ],
        "default": true,
        "enabled": true,
        "rule_id": ".m.rule.invite_for_me"
      },
      {
        "actions": [
          "notify",
          {
            "set_tweak": "highlight",
            "value": false
          }
        ],
        "conditions": [
          {
            "key": "type",
            "kind": "event_match",
            "pattern": "m.room.member"
          }
        ],
        "default": true,
        "enabled": true,
        "rule_id": ".m.rule.member_event"
      },
      {
        "actions": [
          "notify",
          {
            "set_tweak": "highlight",
            "value": false
          }
        ],
        "conditions": [
          {
            "key": "type",
            "kind": "event_match",
            "pattern": "m.room.message"
          }
        ],
        "default": true,
        "enabled": true,
        "rule_id": ".m.rule.message"
      }
    ]
  }
}`
