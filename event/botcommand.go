// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/json"
	"fmt"
	"strconv"
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

func (bat BotArgumentType) ValidateValue(value any) bool {
	_, ok := bat.NormalizeValue(value)
	return ok
}

func (bat BotArgumentType) NormalizeValue(value any) (any, bool) {
	switch bat {
	case BotArgumentTypeInteger:
		switch typedValue := value.(type) {
		case int:
			return typedValue, true
		case int64:
			return int(typedValue), true
		case float64:
			return int(typedValue), true
		case json.Number:
			if i, err := typedValue.Int64(); err == nil {
				return int(i), true
			}
		}
	case BotArgumentTypeBoolean:
		bv, ok := value.(bool)
		return bv, ok
	case BotArgumentTypeString, BotArgumentTypeServerName:
		str, ok := value.(string)
		if !ok {
			return nil, false
		}
		return str, bat.validateStringValue(str)
	case BotArgumentTypeUserID, BotArgumentTypeRoomAlias:
		str, ok := value.(string)
		if !ok {
			return nil, false
		} else if bat.validateStringValue(str) {
			return str, true
		} else if parsed, err := id.ParseMatrixURIOrMatrixToURL(str); err != nil {
			return nil, false
		} else if parsed.Sigil1 == '@' && bat == BotArgumentTypeUserID {
			return parsed.UserID(), true
		} else if parsed.Sigil1 == '#' && bat == BotArgumentTypeRoomAlias {
			return parsed.RoomAlias(), true
		}
	case BotArgumentTypeRoomID, BotArgumentTypeEventID:
		switch typedValue := value.(type) {
		case map[string]any, json.RawMessage:
			var riv MSC4391RoomIDValue
			if raw, err := json.Marshal(value); err != nil {
				return nil, false
			} else if err = json.Unmarshal(raw, &riv); err != nil {
				return nil, false
			}
			return &riv, riv.IsValid()
		case *MSC4391RoomIDValue:
			return typedValue, typedValue.IsValid()
		case MSC4391RoomIDValue:
			return &typedValue, typedValue.IsValid()
		}
	}
	return nil, false
}

func (bat BotArgumentType) validateStringValue(value string) bool {
	switch bat {
	case BotArgumentTypeString:
		return true
	case BotArgumentTypeServerName:
		return id.ValidateServerName(value)
	case BotArgumentTypeUserID:
		_, _, err := id.UserID(value).ParseAndValidateRelaxed()
		return err == nil
	case BotArgumentTypeRoomAlias:
		sigil, localpart, serverName := id.ParseCommonIdentifier(value)
		return sigil == '#' && (localpart != "" || serverName != "") &&
			(serverName == "" || id.ValidateServerName(serverName))
	default:
		panic(fmt.Errorf("validateStringValue called with invalid type %s", bat))
	}
}

func (bat BotArgumentType) ParseString(value string) (any, bool) {
	switch bat {
	case BotArgumentTypeInteger:
		intVal, err := strconv.Atoi(value)
		return intVal, err == nil
	case BotArgumentTypeBoolean:
		boolVal, err := strconv.ParseBool(value)
		return boolVal, err == nil
	case BotArgumentTypeString, BotArgumentTypeServerName, BotArgumentTypeUserID:
		return value, bat.validateStringValue(value)
	case BotArgumentTypeRoomAlias:
		if bat.validateStringValue(value) {
			return value, true
		}
		parsed, _ := id.ParseMatrixURIOrMatrixToURL(value)
		if parsed != nil && parsed.Sigil1 == '#' {
			return parsed.RoomAlias(), true
		}
	case BotArgumentTypeRoomID, BotArgumentTypeEventID:
		parsed, err := id.ParseMatrixURIOrMatrixToURL(value)
		if err != nil && bat == BotArgumentTypeRoomID && strings.HasPrefix(value, "!") {
			return &MSC4391RoomIDValue{
				Type:   bat,
				RoomID: id.RoomID(value),
			}, true
		}
		if err != nil || parsed.Sigil1 != '!' || parsed.Sigil2 != '$' {
			return nil, false
		}
		return &MSC4391RoomIDValue{
			Type:    bat,
			RoomID:  parsed.RoomID(),
			Via:     parsed.Via,
			EventID: parsed.EventID(),
		}, true
	}
	return nil, false
}

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

func (riv *MSC4391RoomIDValue) IsValid() bool {
	if riv == nil {
		return false
	}
	switch riv.Type {
	case BotArgumentTypeRoomID:
		if riv.EventID != "" {
			return false
		}
	case BotArgumentTypeEventID:
		if !strings.HasPrefix(riv.EventID.String(), "$") {
			return false
		}
	default:
		return false
	}
	for _, via := range riv.Via {
		if !id.ValidateServerName(via) {
			return false
		}
	}
	sigil, localpart, serverName := id.ParseCommonIdentifier(riv.RoomID)
	return sigil == '!' &&
		(localpart != "" || serverName != "") &&
		(serverName == "" || id.ValidateServerName(serverName))
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
	Type         *MSC4391ParameterSchema  `json:"type"`
	Optional     bool                     `json:"optional,omitempty"`
	Description  *ExtensibleTextContainer `json:"description,omitempty"`
	DefaultValue any                      `json:"default_value,omitempty"`
}

func (p *MSC4391Parameter) IsValid() bool {
	return p != nil && p.Key != "" && p.Type.IsValid()
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
