// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cmdschema

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"slices"

	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type EventContent struct {
	Command     string                         `json:"command"`
	Aliases     []string                       `json:"aliases,omitempty"`
	Parameters  []*Parameter                   `json:"parameters,omitempty"`
	Description *event.ExtensibleTextContainer `json:"description,omitempty"`
}

func (ec *EventContent) Validate() error {
	if ec == nil {
		return fmt.Errorf("event content is nil")
	} else if ec.Command == "" {
		return fmt.Errorf("command is empty")
	}
	for i, p := range ec.Parameters {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("parameter %q (#%d) is invalid: %w", ptr.Val(p).Key, i+1, err)
		}
	}
	return nil
}

func (ec *EventContent) IsValid() bool {
	return ec.Validate() == nil
}

func (ec *EventContent) StateKey(owner id.UserID) string {
	hash := sha256.Sum256([]byte(ec.Command + owner.String()))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (ec *EventContent) Equals(other *EventContent) bool {
	if ec == nil || other == nil {
		return ec == other
	}
	return ec.Command == other.Command &&
		slices.Equal(ec.Aliases, other.Aliases) &&
		slices.EqualFunc(ec.Parameters, other.Parameters, (*Parameter).Equals) &&
		ec.Description.Equals(other.Description)
}

func init() {
	event.TypeMap[event.StateMSC4391BotCommand] = reflect.TypeOf(EventContent{})
}
