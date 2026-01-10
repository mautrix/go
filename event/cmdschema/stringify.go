// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cmdschema

import (
	"encoding/json"
	"strconv"
	"strings"
)

var quoteEscaper = strings.NewReplacer(
	`"`, `\"`,
	`\`, `\\`,
)

const charsToQuote = ` \` + botArrayOpener + botArrayCloser

func quoteString(val string) string {
	if val == "" {
		return `""`
	}
	val = quoteEscaper.Replace(val)
	if strings.ContainsAny(val, charsToQuote) {
		return `"` + val + `"`
	}
	return val
}

func (ec *EventContent) StringifyArgs(args any) string {
	var argMap map[string]any
	switch typedArgs := args.(type) {
	case json.RawMessage:
		err := json.Unmarshal(typedArgs, &argMap)
		if err != nil {
			return ""
		}
	case map[string]any:
		argMap = typedArgs
	default:
		if b, err := json.Marshal(args); err != nil {
			return ""
		} else if err = json.Unmarshal(b, &argMap); err != nil {
			return ""
		}
	}
	parts := make([]string, 0, len(ec.Parameters))
	for i, param := range ec.Parameters {
		isLast := i == len(ec.Parameters)-1
		val := argMap[param.Key]
		if val == nil {
			val = param.DefaultValue
			if val == nil && !param.Optional {
				val = param.Schema.GetDefaultValue()
			}
		}
		if val == nil {
			continue
		}
		var stringified string
		if param.Schema.SchemaType == SchemaTypeArray {
			stringified = arrayArgumentToString(val, isLast)
		} else {
			stringified = singleArgumentToString(val)
		}
		if stringified != "" {
			parts = append(parts, stringified)
		}
	}
	return strings.Join(parts, " ")
}

func arrayArgumentToString(val any, isLast bool) string {
	valArr, ok := val.([]any)
	if !ok {
		return ""
	}
	parts := make([]string, 0, len(valArr))
	for _, elem := range valArr {
		stringified := singleArgumentToString(elem)
		if stringified != "" {
			parts = append(parts, stringified)
		}
	}
	joinedParts := strings.Join(parts, " ")
	if isLast && len(parts) > 0 {
		return joinedParts
	}
	return botArrayOpener + joinedParts + botArrayCloser
}

func singleArgumentToString(val any) string {
	switch typedVal := val.(type) {
	case string:
		return quoteString(typedVal)
	case json.Number:
		return typedVal.String()
	case bool:
		return strconv.FormatBool(typedVal)
	case int:
		return strconv.Itoa(typedVal)
	case int64:
		return strconv.FormatInt(typedVal, 10)
	case float64:
		return strconv.FormatInt(int64(typedVal), 10)
	case map[string]any, json.RawMessage, RoomIDValue, *RoomIDValue:
		normalized, err := NormalizeRoomIDValue(typedVal)
		if err != nil {
			return ""
		}
		uri := normalized.URI()
		if uri == nil {
			return ""
		}
		return quoteString(uri.String())
	default:
		return ""
	}
}
