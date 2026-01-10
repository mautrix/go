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

	"go.mau.fi/util/exslices"

	"maunium.net/go/mautrix/event"
)

type Parameter struct {
	Key          string                         `json:"key"`
	Schema       *ParameterSchema               `json:"schema"`
	Optional     bool                           `json:"optional,omitempty"`
	Description  *event.ExtensibleTextContainer `json:"description,omitempty"`
	DefaultValue any                            `json:"fi.mau.default_value,omitempty"`
}

func (p *Parameter) Equals(other *Parameter) bool {
	if p == nil || other == nil {
		return p == other
	}
	return p.Key == other.Key &&
		p.Schema.Equals(other.Schema) &&
		p.Optional == other.Optional &&
		p.Description.Equals(other.Description) &&
		p.DefaultValue == other.DefaultValue // TODO this won't work for room/event ID values
}

func (p *Parameter) Validate() error {
	if p == nil {
		return fmt.Errorf("parameter is nil")
	} else if p.Key == "" {
		return fmt.Errorf("key is empty")
	}
	return p.Schema.Validate()
}

func (p *Parameter) IsValid() bool {
	return p.Validate() == nil
}

func (p *Parameter) GetDefaultValue() any {
	if p != nil && p.DefaultValue != nil {
		return p.DefaultValue
	} else if p == nil || p.Optional {
		return nil
	}
	return p.Schema.GetDefaultValue()
}

type PrimitiveType string

const (
	PrimitiveTypeString     PrimitiveType = "string"
	PrimitiveTypeInteger    PrimitiveType = "integer"
	PrimitiveTypeBoolean    PrimitiveType = "boolean"
	PrimitiveTypeServerName PrimitiveType = "server_name"
	PrimitiveTypeUserID     PrimitiveType = "user_id"
	PrimitiveTypeRoomID     PrimitiveType = "room_id"
	PrimitiveTypeRoomAlias  PrimitiveType = "room_alias"
	PrimitiveTypeEventID    PrimitiveType = "event_id"
)

func (pt PrimitiveType) Schema() *ParameterSchema {
	return &ParameterSchema{
		SchemaType: SchemaTypePrimitive,
		Type:       pt,
	}
}

func (pt PrimitiveType) IsValid() bool {
	switch pt {
	case PrimitiveTypeString,
		PrimitiveTypeInteger,
		PrimitiveTypeBoolean,
		PrimitiveTypeServerName,
		PrimitiveTypeUserID,
		PrimitiveTypeRoomID,
		PrimitiveTypeRoomAlias,
		PrimitiveTypeEventID:
		return true
	default:
		return false
	}
}

type SchemaType string

const (
	SchemaTypePrimitive SchemaType = "primitive"
	SchemaTypeArray     SchemaType = "array"
	SchemaTypeUnion     SchemaType = "union"
	SchemaTypeLiteral   SchemaType = "literal"
)

type ParameterSchema struct {
	SchemaType SchemaType         `json:"schema_type"`
	Type       PrimitiveType      `json:"type,omitempty"`     // Only for primitive
	Items      *ParameterSchema   `json:"items,omitempty"`    // Only for array
	Variants   []*ParameterSchema `json:"variants,omitempty"` // Only for union
	Value      any                `json:"value,omitempty"`    // Only for literal
}

func Literal(value any) *ParameterSchema {
	return &ParameterSchema{
		SchemaType: SchemaTypeLiteral,
		Value:      value,
	}
}

func Enum(values ...any) *ParameterSchema {
	return Union(exslices.CastFunc(values, Literal)...)
}

func flattenUnion(variants []*ParameterSchema) []*ParameterSchema {
	var flattened []*ParameterSchema
	for _, variant := range variants {
		switch variant.SchemaType {
		case SchemaTypeArray:
			panic(fmt.Errorf("illegal array schema in union"))
		case SchemaTypeUnion:
			flattened = append(flattened, flattenUnion(variant.Variants)...)
		default:
			flattened = append(flattened, variant)
		}
	}
	return flattened
}

func Union(variants ...*ParameterSchema) *ParameterSchema {
	needsFlattening := false
	for _, variant := range variants {
		if variant.SchemaType == SchemaTypeArray {
			panic(fmt.Errorf("illegal array schema in union"))
		} else if variant.SchemaType == SchemaTypeUnion {
			needsFlattening = true
		}
	}
	if needsFlattening {
		variants = flattenUnion(variants)
	}
	return &ParameterSchema{
		SchemaType: SchemaTypeUnion,
		Variants:   variants,
	}
}

func Array(items *ParameterSchema) *ParameterSchema {
	if items.SchemaType == SchemaTypeArray {
		panic(fmt.Errorf("illegal array schema in array"))
	}
	return &ParameterSchema{
		SchemaType: SchemaTypeArray,
		Items:      items,
	}
}

func (ps *ParameterSchema) GetDefaultValue() any {
	if ps == nil {
		return nil
	}
	switch ps.SchemaType {
	case SchemaTypePrimitive:
		switch ps.Type {
		case PrimitiveTypeInteger:
			return 0
		case PrimitiveTypeBoolean:
			return false
		default:
			return ""
		}
	case SchemaTypeArray:
		return []any{}
	case SchemaTypeUnion:
		if len(ps.Variants) > 0 {
			return ps.Variants[0].GetDefaultValue()
		}
		return nil
	case SchemaTypeLiteral:
		return ps.Value
	default:
		return nil
	}
}

func (ps *ParameterSchema) IsValid() bool {
	return ps.validate("") == nil
}

func (ps *ParameterSchema) Validate() error {
	return ps.validate("")
}

func (ps *ParameterSchema) validate(parent SchemaType) error {
	if ps == nil {
		return fmt.Errorf("schema is nil")
	}
	switch ps.SchemaType {
	case SchemaTypePrimitive:
		if !ps.Type.IsValid() {
			return fmt.Errorf("invalid primitive type %s", ps.Type)
		} else if ps.Items != nil || ps.Variants != nil || ps.Value != nil {
			return fmt.Errorf("primitive schema has extra fields")
		}
		return nil
	case SchemaTypeArray:
		if parent != "" {
			return fmt.Errorf("arrays can't be nested in other types")
		} else if err := ps.Items.validate(ps.SchemaType); err != nil {
			return fmt.Errorf("item schema is invalid: %w", err)
		} else if ps.Type != "" || ps.Variants != nil || ps.Value != nil {
			return fmt.Errorf("array schema has extra fields")
		}
		return nil
	case SchemaTypeUnion:
		if len(ps.Variants) == 0 {
			return fmt.Errorf("no variants specified for union")
		} else if parent != "" && parent != SchemaTypeArray {
			return fmt.Errorf("unions can't be nested in anything other than arrays")
		}
		for i, v := range ps.Variants {
			if err := v.validate(ps.SchemaType); err != nil {
				return fmt.Errorf("variant #%d is invalid: %w", i+1, err)
			}
		}
		if ps.Type != "" || ps.Items != nil || ps.Value != nil {
			return fmt.Errorf("union schema has extra fields")
		}
		return nil
	case SchemaTypeLiteral:
		switch typedVal := ps.Value.(type) {
		case string, float64, int, int64, json.Number, bool, RoomIDValue, *RoomIDValue:
			// ok
		case map[string]any:
			if typedVal["type"] != "event_id" && typedVal["type"] != "room_id" {
				return fmt.Errorf("literal value has invalid map data")
			}
		default:
			return fmt.Errorf("literal value has unsupported type %T", ps.Value)
		}
		if ps.Type != "" || ps.Items != nil || ps.Variants != nil {
			return fmt.Errorf("literal schema has extra fields")
		}
		return nil
	default:
		return fmt.Errorf("invalid schema type %s", ps.SchemaType)
	}
}

func (ps *ParameterSchema) Equals(other *ParameterSchema) bool {
	if ps == nil || other == nil {
		return ps == other
	}
	return ps.SchemaType == other.SchemaType &&
		ps.Type == other.Type &&
		ps.Items.Equals(other.Items) &&
		slices.EqualFunc(ps.Variants, other.Variants, (*ParameterSchema).Equals) &&
		ps.Value == other.Value // TODO this won't work for room/event ID values
}

func (ps *ParameterSchema) AllowsPrimitive(prim PrimitiveType) bool {
	switch ps.SchemaType {
	case SchemaTypePrimitive:
		return ps.Type == prim
	case SchemaTypeUnion:
		for _, variant := range ps.Variants {
			if variant.AllowsPrimitive(prim) {
				return true
			}
		}
		return false
	case SchemaTypeArray:
		return ps.Items.AllowsPrimitive(prim)
	default:
		return false
	}
}
