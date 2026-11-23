// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pushrules

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// PushActionType is the type of a PushAction
type PushActionType string

// The allowed push action types as specified in spec section 11.12.1.4.1.
const (
	ActionNotify   PushActionType = "notify"
	ActionSetTweak PushActionType = "set_tweak"
	// Deprecated: this does nothing. An empty actions array is equivalent
	ActionDontNotify PushActionType = "dont_notify"
	// Deprecated: this was never implemented and was removed from the Matrix spec
	ActionCoalesce PushActionType = "coalesce"
)

// PushActionTweak is the type of the tweak in SetTweak push actions.
type PushActionTweak string

// The allowed tweak types as specified in spec section 11.12.1.4.1.1.
const (
	TweakSound     PushActionTweak = "sound"
	TweakHighlight PushActionTweak = "highlight"
)

// PushActionArray is an array of PushActions.
type PushActionArray []*PushAction

// PushActionArrayShould contains the important information parsed from a PushActionArray.
type PushActionArrayShould struct {
	// Whether the event in question should trigger a notification.
	Notify bool
	// Whether the event in question should be highlighted.
	Highlight bool

	// Whether the event in question should trigger a sound alert.
	PlaySound bool
	// The name of the sound to play if PlaySound is true.
	SoundName string
}

var ShouldDoNothing = PushActionArrayShould{}

// Should parses this push action array and returns the relevant details wrapped in a PushActionArrayShould struct.
func (actions PushActionArray) Should() (should PushActionArrayShould) {
	for _, action := range actions {
		switch action.Action {
		case ActionNotify, ActionCoalesce:
			should.Notify = true
		case ActionSetTweak:
			switch action.Tweak {
			case TweakHighlight:
				var ok bool
				should.Highlight, ok = action.Value.(bool)
				if !ok {
					// Highlight value not specified, so assume true since the tweak is set.
					should.Highlight = true
				}
			case TweakSound:
				should.SoundName = action.Value.(string)
				should.PlaySound = len(should.SoundName) > 0
			}
		}
	}
	return
}

// PushAction is a single action that should be triggered when receiving a message.
type PushAction struct {
	Action PushActionType  `json:"action"`
	Tweak  PushActionTweak `json:"set_tweak,omitempty"`
	Value  any             `json:"value,omitzero"`
}

// UnmarshalJSONFrom parses JSON into this PushAction.
//
//   - If the JSON is a single string, the value is stored in the Action field.
//   - If the JSON is an object with the set_tweak field, Action will be set to
//     "set_tweak", Tweak will be set to the value of the set_tweak field and
//     and Value will be set to the value of the value field.
//   - In any other case, the function does nothing.
func (action *PushAction) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var data any

	err := json.UnmarshalDecode(dec, &data)
	if err != nil {
		return err
	}

	switch val := data.(type) {
	case string:
		action.Action = PushActionType(val)
	case map[string]any:
		if tweak, ok := val["set_tweak"].(string); ok {
			action.Action = ActionSetTweak
			action.Tweak = PushActionTweak(tweak)
			action.Value = val["value"]
		} else if actionVal, ok := val["action"].(string); ok {
			action.Action = PushActionType(actionVal)
		}
	}
	return nil
}

// MarshalJSONTo is the reverse of UnmarshalJSONFrom()
func (action *PushAction) MarshalJSONTo(enc *jsontext.Encoder) error {
	if action.Action == ActionSetTweak {
		return json.MarshalEncode(enc, struct {
			SetTweak PushActionTweak `json:"set_tweak"`
			Value    any             `json:"value"`
		}{action.Tweak, action.Value})
	}
	return enc.WriteToken(jsontext.String(string(action.Action)))
}
