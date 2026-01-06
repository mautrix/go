// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"maunium.net/go/mautrix/id"
)

const botArrayOpener = "<"
const botArrayCloser = ">"

func parseQuoted(val string) (parsed, remaining string, quoted bool) {
	if len(val) == 0 {
		return
	}
	if !strings.HasPrefix(val, `"`) {
		spaceIdx := strings.IndexByte(val, ' ')
		if spaceIdx == -1 {
			parsed = val
		} else {
			parsed = val[:spaceIdx]
			remaining = strings.TrimLeft(val[spaceIdx+1:], " ")
		}
		return
	}
	val = val[1:]
	var buf strings.Builder
	for {
		quoteIdx := strings.IndexByte(val, '"')
		escapeIdx := strings.IndexByte(val[:max(0, quoteIdx)], '\\')
		if escapeIdx >= 0 {
			buf.WriteString(val[:escapeIdx])
			if len(val) > escapeIdx+1 {
				buf.WriteByte(val[escapeIdx+1])
			}
			val = val[min(escapeIdx+2, len(val)):]
		} else if quoteIdx > 0 {
			buf.WriteString(val[:quoteIdx])
			val = val[quoteIdx+1:]
			break
		} else if buf.Len() == 0 {
			// Unterminated quote, no escape characters, val is the whole input
			return val, "", true
		} else {
			// Unterminated quote, but there were escape characters previously
			buf.WriteString(val)
			val = ""
			break
		}
	}
	return buf.String(), strings.TrimLeft(val, " "), true
}

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

func (bcec *MSC4391BotCommandEventContent) StringifyArgs(args *MSC4391BotCommandInput) string {
	var buf strings.Builder
	// TODO implement
	return quoteString(buf.String())
}

// ParseInput tries to parse the given text into a bot command event matching this command definition.
//
// If the prefix doesn't match, this will return a nil content and nil error.
// If the prefix does match, some content is always returned, but there may still be an error if parsing failed.
func (bcec *MSC4391BotCommandEventContent) ParseInput(owner id.UserID, sigil, input string) (*MessageEventContent, error) {
	fullInput := input
	prefix := bcec.parsePrefix(input, sigil, owner.String())
	if prefix == "" {
		return nil, nil
	}
	input = input[len(prefix):]
	args := make(map[string]any)
	var retErr error
	setError := func(err error) {
		if err != nil && retErr == nil {
			retErr = err
		}
	}
	for i, param := range bcec.Parameters {
		isLast := i == len(bcec.Parameters)-1
		origInput := input
		var nextVal string
		var wasQuoted bool
		if param.Schema.SchemaType == MSC4391SchemaTypeArray {
			hasOpener := strings.HasPrefix(input, botArrayOpener)
			arrayClosed := false
			if hasOpener {
				input = input[len(botArrayOpener):]
				if strings.HasPrefix(input, botArrayCloser) {
					input = strings.TrimLeft(input[len(botArrayCloser):], " ")
					arrayClosed = true
				}
			}
			var collector []any
			for len(input) > 0 && !arrayClosed {
				origInput = input
				nextVal, input, wasQuoted = parseQuoted(input)
				if !wasQuoted && hasOpener && strings.HasSuffix(nextVal, botArrayCloser) {
					// The value wasn't quoted and has the array delimiter at the end, close the array
					nextVal = strings.TrimRight(nextVal, botArrayCloser)
					arrayClosed = true
				} else if hasOpener && strings.HasPrefix(input, botArrayCloser) {
					// The value was quoted or there was a space, and the next character is the
					// array delimiter, close the array
					input = strings.TrimLeft(input[len(botArrayCloser):], " ")
					arrayClosed = true
				} else if !hasOpener && !isLast {
					// For array arguments in the middle without the <> delimiters, stop after the first item
					arrayClosed = true
				}
				parsedVal, err := param.Schema.ParseString(nextVal)
				if err == nil {
					collector = append(collector, parsedVal)
				} else if hasOpener || isLast {
					setError(fmt.Errorf("failed to parse item #%d of array %s: %w", len(collector)+1, param.Key, err))
				} else {
					//input = origInput
				}
			}
			args[param.Key] = collector
		} else {
			nextVal, input, wasQuoted = parseQuoted(input)
			if isLast && !wasQuoted && len(input) > 0 {
				// If the last argument is not quoted and not variadic, just treat the rest of the string
				// as the argument without escapes (arguments with escapes should be quoted).
				nextVal += " " + input
				input = ""
			}
			parsedVal, err := param.Schema.ParseString(nextVal)
			if err != nil {
				args[param.Key] = param.GetDefaultValue()
				// For optional parameters that fail to parse, restore the input and try passing it as the next parameter
				if param.Optional && !isLast {
					input = origInput
				} else if !param.Optional {
					setError(fmt.Errorf("failed to parse %s: %w", param.Key, err))
				}
			} else {
				args[param.Key] = parsedVal
			}
		}
	}
	content := &MessageEventContent{
		MsgType:  MsgText,
		Body:     fullInput,
		Mentions: &Mentions{UserIDs: []id.UserID{owner}},
		MSC4391BotCommand: &MSC4391BotCommandInput{
			Command: bcec.Command,
		},
	}
	var marshalErr error
	content.MSC4391BotCommand.Arguments, marshalErr = json.Marshal(args)
	if marshalErr != nil {
		return content, fmt.Errorf("failed to marshal arguments: %w", marshalErr)
	}
	return content, retErr
}

func (bcec *MSC4391BotCommandEventContent) parsePrefix(origInput, sigil, owner string) (prefix string) {
	input := origInput
	if !strings.HasPrefix(input, sigil) {
		return ""
	}
	input = input[len(sigil):]
	var chosenAlias string
	if !strings.HasPrefix(input, bcec.Command) {
		for _, alias := range bcec.Aliases {
			if strings.HasPrefix(input, alias) {
				chosenAlias = alias
				break
			}
		}
		if chosenAlias == "" {
			return ""
		}
	} else {
		chosenAlias = bcec.Command
	}
	input = strings.TrimPrefix(input[len(chosenAlias):], owner)
	if input == "" || input[0] == ' ' {
		input = strings.TrimLeft(input, " ")
		return origInput[:len(origInput)-len(input)]
	}
	return ""
}

func (bat BotArgumentType) ValidateValue(value any) bool {
	_, err := bat.NormalizeValue(value)
	return err == nil
}

func normalizeNumber(value any) (int, error) {
	switch typedValue := value.(type) {
	case int:
		return typedValue, nil
	case int64:
		return int(typedValue), nil
	case float64:
		return int(typedValue), nil
	case json.Number:
		if i, err := typedValue.Int64(); err != nil {
			return 0, fmt.Errorf("failed to parse json.Number: %w", err)
		} else {
			return int(i), nil
		}
	default:
		return 0, fmt.Errorf("unsupported type %T for integer", value)
	}
}

func (bat BotArgumentType) NormalizeValue(value any) (any, error) {
	switch bat {
	case BotArgumentTypeInteger:
		return normalizeNumber(value)
	case BotArgumentTypeBoolean:
		bv, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("unsupported type %T for boolean", value)
		}
		return bv, nil
	case BotArgumentTypeString, BotArgumentTypeServerName:
		str, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("unsupported type %T for string", value)
		}
		return str, bat.validateStringValue(str)
	case BotArgumentTypeUserID, BotArgumentTypeRoomAlias:
		str, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("unsupported type %T for user ID or room alias", value)
		} else if plainErr := bat.validateStringValue(str); plainErr == nil {
			return str, nil
		} else if parsed, err := id.ParseMatrixURIOrMatrixToURL(str); err != nil {
			return nil, fmt.Errorf("couldn't parse %q as plain ID nor matrix URI: %w / %w", value, plainErr, err)
		} else if parsed.Sigil1 == '@' && bat == BotArgumentTypeUserID {
			return parsed.UserID(), nil
		} else if parsed.Sigil1 == '#' && bat == BotArgumentTypeRoomAlias {
			return parsed.RoomAlias(), nil
		} else {
			return nil, fmt.Errorf("unexpected sigil %c for user ID or room alias", parsed.Sigil1)
		}
	case BotArgumentTypeRoomID, BotArgumentTypeEventID:
		riv, err := NormalizeRoomIDValue(value)
		if err != nil {
			return nil, err
		}
		return riv, riv.Validate()
	default:
		return nil, fmt.Errorf("cannot normalize value for argument type %s", bat)
	}
}

func (bat BotArgumentType) validateStringValue(value string) error {
	switch bat {
	case BotArgumentTypeString:
		return nil
	case BotArgumentTypeServerName:
		if !id.ValidateServerName(value) {
			return fmt.Errorf("invalid server name: %q", value)
		}
		return nil
	case BotArgumentTypeUserID:
		_, _, err := id.UserID(value).ParseAndValidateRelaxed()
		return err
	case BotArgumentTypeRoomAlias:
		sigil, localpart, serverName := id.ParseCommonIdentifier(value)
		if sigil != '#' || localpart == "" || serverName == "" {
			return fmt.Errorf("invalid room alias: %q", value)
		} else if !id.ValidateServerName(serverName) {
			return fmt.Errorf("invalid server name in room alias: %q", serverName)
		}
		return nil
	default:
		panic(fmt.Errorf("validateStringValue called with invalid type %s", bat))
	}
}

func parseBoolean(val string) (bool, error) {
	if len(val) == 0 {
		return false, fmt.Errorf("cannot parse empty string as boolean")
	}
	switch val[0] {
	case 't', 'T', 'y', 'Y', '1':
		return true, nil
	case 'f', 'F', 'n', 'N', '0':
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean string: %q", val)
	}
}

var markdownLinkRegex = regexp.MustCompile(`^\[.+]\(([^)]+)\)$`)

func parseRoomOrEventID(value string) (*MSC4391RoomIDValue, error) {
	if strings.HasPrefix(value, "[") && strings.Contains(value, "](") && strings.HasSuffix(value, ")") {
		matches := markdownLinkRegex.FindStringSubmatch(value)
		if len(matches) == 2 {
			value = matches[1]
		}
	}
	parsed, err := id.ParseMatrixURIOrMatrixToURL(value)
	if err != nil && strings.HasPrefix(value, "!") {
		return &MSC4391RoomIDValue{
			Type:   BotArgumentTypeRoomID,
			RoomID: id.RoomID(value),
		}, nil
	}
	if err != nil {
		return nil, err
	} else if parsed.Sigil1 != '!' {
		return nil, fmt.Errorf("unexpected sigil %c for room ID", parsed.Sigil1)
	} else if parsed.MXID2 != "" && parsed.Sigil2 != '$' {
		return nil, fmt.Errorf("unexpected sigil %c for event ID", parsed.Sigil2)
	}
	valType := BotArgumentTypeRoomID
	if parsed.MXID2 != "" {
		valType = BotArgumentTypeEventID
	}
	return &MSC4391RoomIDValue{
		Type:    valType,
		RoomID:  parsed.RoomID(),
		Via:     parsed.Via,
		EventID: parsed.EventID(),
	}, nil
}

func (bat BotArgumentType) ParseString(value string) (any, error) {
	switch bat {
	case BotArgumentTypeInteger:
		return strconv.Atoi(value)
	case BotArgumentTypeBoolean:
		return parseBoolean(value)
	case BotArgumentTypeString, BotArgumentTypeServerName, BotArgumentTypeUserID:
		return value, bat.validateStringValue(value)
	case BotArgumentTypeRoomAlias:
		plainErr := bat.validateStringValue(value)
		if plainErr == nil {
			return value, nil
		}
		parsed, err := id.ParseMatrixURIOrMatrixToURL(value)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse %q as plain room alias nor matrix URI: %w / %w", value, plainErr, err)
		} else if parsed.Sigil1 != '#' {
			return nil, fmt.Errorf("unexpected sigil %c for room alias", parsed.Sigil1)
		}
		return parsed.RoomAlias(), nil
	case BotArgumentTypeRoomID, BotArgumentTypeEventID:
		parsed, err := parseRoomOrEventID(value)
		if err != nil {
			return nil, err
		} else if bat != parsed.Type {
			return nil, fmt.Errorf("mismatching argument type: expected %s but got %s", bat, parsed.Type)
		}
		return bat, nil
	default:
		return nil, fmt.Errorf("cannot parse string for argument type %s", bat)
	}
}

func (ps *MSC4391ParameterSchema) ParseString(value string) (any, error) {
	if ps == nil {
		return nil, fmt.Errorf("parameter schema is nil")
	}
	switch ps.SchemaType {
	case MSC4391SchemaTypePrimitive:
		return ps.Type.ParseString(value)
	case MSC4391SchemaTypeLiteral:
		switch typedValue := ps.Value.(type) {
		case string:
			if value == typedValue {
				return typedValue, nil
			} else {
				return nil, fmt.Errorf("literal value %q does not match %q", typedValue, value)
			}
		case int, int64, float64, json.Number:
			expectedVal, _ := normalizeNumber(typedValue)
			intVal, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("failed to parse integer literal: %w", err)
			} else if intVal != expectedVal {
				return nil, fmt.Errorf("literal value %d does not match %d", expectedVal, intVal)
			}
			return intVal, nil
		case bool:
			boolVal, err := parseBoolean(value)
			if err != nil {
				return nil, fmt.Errorf("failed to parse boolean literal: %w", err)
			} else if boolVal != typedValue {
				return nil, fmt.Errorf("literal value %t does not match %t", typedValue, boolVal)
			}
			return boolVal, nil
		case MSC4391RoomIDValue, *MSC4391RoomIDValue, map[string]any, json.RawMessage:
			expectedVal, _ := NormalizeRoomIDValue(typedValue)
			parsed, err := parseRoomOrEventID(value)
			if err != nil {
				return nil, fmt.Errorf("failed to parse room or event ID literal: %w", err)
			} else if !parsed.Equals(expectedVal) {
				return nil, fmt.Errorf("literal value %s does not match %s", expectedVal, parsed)
			}
			return parsed, nil
		default:
			return nil, fmt.Errorf("unsupported literal type %T", ps.Value)
		}
	case MSC4391SchemaTypeUnion:
		var errs []error
		for _, variant := range ps.Variants {
			if parsed, err := variant.ParseString(value); err == nil {
				return parsed, nil
			} else {
				errs = append(errs, err)
			}
		}
		return nil, fmt.Errorf("no union variant matched: %w", errors.Join(errs...))
	case MSC4391SchemaTypeArray:
		return nil, fmt.Errorf("cannot parse string for array schema type")
	default:
		return nil, fmt.Errorf("unknown schema type %s", ps.SchemaType)
	}
}
