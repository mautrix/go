// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cmdschema

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"maunium.net/go/mautrix/id"
)

var ParameterSchemaJoinableRoom = Union(
	PrimitiveTypeRoomID.Schema(),
	PrimitiveTypeRoomAlias.Schema(),
)

type RoomIDValue struct {
	Type    PrimitiveType `json:"type"`
	RoomID  id.RoomID     `json:"id"`
	Via     []string      `json:"via,omitempty"`
	EventID id.EventID    `json:"event_id,omitempty"`
}

func NormalizeRoomIDValue(input any) (riv *RoomIDValue, err error) {
	switch typedValue := input.(type) {
	case map[string]any, json.RawMessage:
		var raw json.RawMessage
		if raw, err = json.Marshal(input); err != nil {
			err = fmt.Errorf("failed to roundtrip room ID value: %w", err)
		} else if err = json.Unmarshal(raw, &riv); err != nil {
			err = fmt.Errorf("failed to roundtrip room ID value: %w", err)
		}
	case *RoomIDValue:
		riv = typedValue
	case RoomIDValue:
		riv = &typedValue
	default:
		err = fmt.Errorf("unsupported type %T for room or event ID", input)
	}
	return
}

func (riv *RoomIDValue) String() string {
	return riv.URI().String()
}

func (riv *RoomIDValue) URI() *id.MatrixURI {
	if riv == nil {
		return nil
	}
	switch riv.Type {
	case PrimitiveTypeRoomID:
		return riv.RoomID.URI(riv.Via...)
	case PrimitiveTypeEventID:
		return riv.RoomID.EventURI(riv.EventID, riv.Via...)
	default:
		return nil
	}
}

func (riv *RoomIDValue) Equals(other *RoomIDValue) bool {
	if riv == nil || other == nil {
		return riv == other
	}
	return riv.Type == other.Type &&
		riv.RoomID == other.RoomID &&
		riv.EventID == other.EventID &&
		slices.Equal(riv.Via, other.Via)
}

func (riv *RoomIDValue) Validate() error {
	if riv == nil {
		return fmt.Errorf("value is nil")
	}
	switch riv.Type {
	case PrimitiveTypeRoomID:
		if riv.EventID != "" {
			return fmt.Errorf("event ID must be empty for room ID type")
		}
	case PrimitiveTypeEventID:
		if !strings.HasPrefix(riv.EventID.String(), "$") {
			return fmt.Errorf("event ID not valid: %q", riv.EventID)
		}
	default:
		return fmt.Errorf("unexpected type %s for room/event ID value", riv.Type)
	}
	for _, via := range riv.Via {
		if !id.ValidateServerName(via) {
			return fmt.Errorf("invalid server name %q in vias", via)
		}
	}
	sigil, localpart, serverName := id.ParseCommonIdentifier(riv.RoomID)
	if sigil != '!' {
		return fmt.Errorf("room ID does not start with !: %q", riv.RoomID)
	} else if localpart == "" && serverName == "" {
		return fmt.Errorf("room ID has empty localpart and server name: %q", riv.RoomID)
	} else if serverName != "" && !id.ValidateServerName(serverName) {
		return fmt.Errorf("invalid server name %q in room ID", serverName)
	}
	return nil
}

func (riv *RoomIDValue) IsValid() bool {
	return riv.Validate() == nil
}

type RoomIDOrString string

func (ros *RoomIDOrString) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for room ID or string")
	}
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		*ros = RoomIDOrString(str)
		return nil
	}
	var riv RoomIDValue
	if err := json.Unmarshal(data, &riv); err != nil {
		return err
	} else if err = riv.Validate(); err != nil {
		return err
	}
	*ros = RoomIDOrString(riv.String())
	return nil
}
