// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"strings"
)

// A PreValidator contains a function that takes an Event and returns true if the event should be processed further.
//
// The [PreValidator] field in [Processor] is called before the handler of the command is checked.
// It can be used to modify the command or arguments, or to skip the command entirely.
//
// The primary use case is removing a static command prefix, such as requiring all commands start with `!`.
type PreValidator[MetaType any] interface {
	Validate(*Event[MetaType]) bool
}

// FuncPreValidator is a simple function that implements the PreValidator interface.
type FuncPreValidator[MetaType any] func(*Event[MetaType]) bool

func (f FuncPreValidator[MetaType]) Validate(ce *Event[MetaType]) bool {
	return f(ce)
}

// AllPreValidator can be used to combine multiple PreValidators, such that
// all of them must return true for the command to be processed further.
type AllPreValidator[MetaType any] []PreValidator[MetaType]

func (f AllPreValidator[MetaType]) Validate(ce *Event[MetaType]) bool {
	for _, validator := range f {
		if !validator.Validate(ce) {
			return false
		}
	}
	return true
}

// AnyPreValidator can be used to combine multiple PreValidators, such that
// at least one of them must return true for the command to be processed further.
type AnyPreValidator[MetaType any] []PreValidator[MetaType]

func (f AnyPreValidator[MetaType]) Validate(ce *Event[MetaType]) bool {
	for _, validator := range f {
		if validator.Validate(ce) {
			return true
		}
	}
	return false
}

// ValidatePrefixCommand checks that the first word in the input is exactly the given string,
// and if so, removes it from the command and sets the command to the next word.
//
// For example, `ValidateCommandPrefix("!mybot")` would only allow commands in the form `!mybot foo`,
// where `foo` would be used to look up the command handler.
func ValidatePrefixCommand[MetaType any](prefix string) PreValidator[MetaType] {
	return FuncPreValidator[MetaType](func(ce *Event[MetaType]) bool {
		if ce.Command == prefix && len(ce.Args) > 0 {
			ce.Command = strings.ToLower(ce.ShiftArg())
			return true
		}
		return false
	})
}

// ValidatePrefixSubstring checks that the command starts with the given prefix,
// and if so, removes it from the command.
//
// For example, `ValidatePrefixSubstring("!")` would only allow commands in the form `!foo`,
// where `foo` would be used to look up the command handler.
func ValidatePrefixSubstring[MetaType any](prefix string) PreValidator[MetaType] {
	return FuncPreValidator[MetaType](func(ce *Event[MetaType]) bool {
		if strings.HasPrefix(ce.Command, prefix) {
			ce.Command = ce.Command[len(prefix):]
			return true
		}
		return false
	})
}
