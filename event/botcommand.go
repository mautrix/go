// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/json"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/id"
)

type MSC4332BotCommandsEventContent struct {
	Sigil    string               `json:"sigil,omitempty"`
	Commands []*MSC4332BotCommand `json:"commands,omitempty"`
}

type MSC4332BotCommand struct {
	Syntax      string                       `json:"syntax"`
	Aliases     []string                     `json:"fi.mau.aliases,omitempty"` // Not in MSC (yet)
	Arguments   []*MSC4332BotCommandArgument `json:"arguments,omitempty"`
	Description *ExtensibleTextContainer     `json:"description,omitempty"`
}

type MSC4332BotCommandArgument struct {
	Type         BotArgumentType          `json:"type"`
	DefaultValue any                      `json:"fi.mau.default_value,omitempty"` // Not in MSC (yet)
	Description  *ExtensibleTextContainer `json:"description,omitempty"`
	Enum         []string                 `json:"enum,omitempty"`
	Variadic     bool                     `json:"variadic,omitempty"`
}

type MSC4332BotCommandInput struct {
	Syntax    string          `json:"syntax"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type BotArgumentType string

const (
	BotArgumentTypeString     BotArgumentType = "string"
	BotArgumentTypeEnum       BotArgumentType = "enum"
	BotArgumentTypeInteger    BotArgumentType = "integer"
	BotArgumentTypeBoolean    BotArgumentType = "boolean"
	BotArgumentTypeServerName BotArgumentType = "server_name"
	BotArgumentTypeUserID     BotArgumentType = "user_id"
	BotArgumentTypeRoomID     BotArgumentType = "room_id"
	BotArgumentTypeRoomAlias  BotArgumentType = "room_alias"
	BotArgumentTypeEventID    BotArgumentType = "event_id"
)

func (bat BotArgumentType) Schema() *MSC4391ParameterSchema {
	return &MSC4391ParameterSchema{
		SchemaType: MSC4391SchemaTypePrimitive,
		Type:       bat,
	}
}

func (bat BotArgumentType) IsValid() bool {
	switch bat {
	case BotArgumentTypeString,
		BotArgumentTypeInteger,
		BotArgumentTypeBoolean,
		BotArgumentTypeServerName,
		BotArgumentTypeUserID,
		BotArgumentTypeRoomID,
		BotArgumentTypeRoomAlias,
		BotArgumentTypeEventID:
		return true
	default:
		return false
	}
}

type MSC4391SchemaType string

const (
	MSC4391SchemaTypePrimitive MSC4391SchemaType = "primitive"
	MSC4391SchemaTypeArray     MSC4391SchemaType = "array"
	MSC4391SchemaTypeUnion     MSC4391SchemaType = "union"
	MSC4391SchemaTypeLiteral   MSC4391SchemaType = "literal"
)

func LiteralSchema(value any) *MSC4391ParameterSchema {
	return &MSC4391ParameterSchema{
		SchemaType: MSC4391SchemaTypeLiteral,
		Value:      value,
	}
}

func EnumSchema(values ...any) *MSC4391ParameterSchema {
	var variants []*MSC4391ParameterSchema
	for _, v := range values {
		variants = append(variants, LiteralSchema(v))
	}
	return &MSC4391ParameterSchema{
		SchemaType: MSC4391SchemaTypeUnion,
		Variants:   variants,
	}
}

type MSC4391RoomIDValue struct {
	Type    BotArgumentType `json:"type"`
	RoomID  id.RoomID       `json:"id"`
	Via     []string        `json:"via,omitempty"`
	EventID id.EventID      `json:"event_id,omitempty"`
}

func (riv *MSC4391RoomIDValue) URI() *id.MatrixURI {
	if riv == nil {
		return nil
	}
	switch riv.Type {
	case BotArgumentTypeRoomID:
		return riv.RoomID.URI(riv.Via...)
	case BotArgumentTypeEventID:
		return riv.RoomID.EventURI(riv.EventID, riv.Via...)
	default:
		return nil
	}
}

func (riv *MSC4391RoomIDValue) Validate() error {
	if riv == nil {
		return fmt.Errorf("value is nil")
	}
	switch riv.Type {
	case BotArgumentTypeRoomID:
		if riv.EventID != "" {
			return fmt.Errorf("event ID must be empty for room ID type")
		}
	case BotArgumentTypeEventID:
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

func (riv *MSC4391RoomIDValue) IsValid() bool {
	return riv.Validate() == nil
}

var (
	ParameterSchemaJoinableRoom = &MSC4391ParameterSchema{
		SchemaType: MSC4391SchemaTypeUnion,
		Variants: []*MSC4391ParameterSchema{
			BotArgumentTypeRoomID.Schema(),
			BotArgumentTypeRoomAlias.Schema(),
		},
	}
)

type MSC4391ParameterSchema struct {
	SchemaType MSC4391SchemaType         `json:"schema_type"`
	Type       BotArgumentType           `json:"type,omitempty"`     // Only for primitive
	Items      *MSC4391ParameterSchema   `json:"items,omitempty"`    // Only for array
	Variants   []*MSC4391ParameterSchema `json:"variants,omitempty"` // Only for union
	Value      any                       `json:"value,omitempty"`    // Only for literal
}

func (ps *MSC4391ParameterSchema) GetDefaultValue() any {
	if ps == nil {
		return nil
	}
	switch ps.SchemaType {
	case MSC4391SchemaTypePrimitive:
		switch ps.Type {
		case BotArgumentTypeInteger:
			return 0
		case BotArgumentTypeBoolean:
			return false
		default:
			return ""
		}
	case MSC4391SchemaTypeArray:
		return []any{}
	case MSC4391SchemaTypeUnion:
		if len(ps.Variants) > 0 {
			return ps.Variants[0].GetDefaultValue()
		}
		return nil
	case MSC4391SchemaTypeLiteral:
		return ps.Value
	default:
		return nil
	}
}

func (ps *MSC4391ParameterSchema) IsValid() bool {
	return ps.isValid("")
}

func (ps *MSC4391ParameterSchema) isValid(parent MSC4391SchemaType) bool {
	if ps == nil {
		return false
	}
	switch ps.SchemaType {
	case MSC4391SchemaTypePrimitive:
		return ps.Type.IsValid() && ps.Items == nil && ps.Variants == nil && ps.Value == nil
	case MSC4391SchemaTypeArray:
		if parent != "" {
			return false
		}
		return ps.Items.isValid(ps.SchemaType) && ps.Type == "" && ps.Variants == nil && ps.Value == nil
	case MSC4391SchemaTypeUnion:
		if len(ps.Variants) == 0 {
			return false
		} else if parent != "" && parent != MSC4391SchemaTypeArray {
			return false
		}
		for _, v := range ps.Variants {
			if !v.isValid(ps.SchemaType) {
				return false
			}
		}
		return ps.Type == "" && ps.Variants == nil && ps.Value == nil
	case MSC4391SchemaTypeLiteral:
		switch ps.Value.(type) {
		case string, float64, int, int64, json.Number, bool:
		default:
			return false
		}
		return ps.Type == "" && ps.Items == nil && ps.Variants == nil
	default:
		return false
	}
}

type MSC4391Parameter struct {
	Key          string                   `json:"key"`
	Schema       *MSC4391ParameterSchema  `json:"schema"`
	Optional     bool                     `json:"optional,omitempty"`
	Description  *ExtensibleTextContainer `json:"description,omitempty"`
	DefaultValue any                      `json:"default_value,omitempty"`
}

func (p *MSC4391Parameter) IsValid() bool {
	return p != nil && p.Key != "" && p.Schema.IsValid()
}

func (p *MSC4391Parameter) GetDefaultValue() any {
	if p != nil && p.DefaultValue != nil {
		return p.DefaultValue
	} else if p == nil || p.Optional {
		return nil
	}
	return p.Schema.GetDefaultValue()
}

type MSC4391BotCommandEventContent struct {
	Command     string                   `json:"command"`
	Aliases     []string                 `json:"aliases,omitempty"`
	Parameters  []*MSC4391Parameter      `json:"parameters,omitempty"`
	Description *ExtensibleTextContainer `json:"description,omitempty"`
}

func (bcec *MSC4391BotCommandEventContent) IsValid() bool {
	if bcec == nil || bcec.Command == "" {
		return false
	}
	for _, p := range bcec.Parameters {
		if !p.IsValid() {
			return false
		}
		//if p.Type.SchemaType == MSC4391SchemaTypeArray && i != len(bcec.Parameters)-1 {
		//	return false
		//}
	}
	return true
}

type MSC4391BotCommandInput struct {
	Command   string          `json:"command"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}
