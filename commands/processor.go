// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

// Processor implements boilerplate code for splitting messages into a command and arguments,
// and finding the appropriate handler for the command.
type Processor[MetaType any] struct {
	Client       *mautrix.Client
	LogArgs      bool
	PreValidator PreValidator[MetaType]
	Meta         MetaType
	commands     map[string]*Handler[MetaType]
	aliases      map[string]string
	lock         sync.RWMutex
}

type Handler[MetaType any] struct {
	Func func(ce *Event[MetaType])

	// Name is the primary name of the command. It must be lowercase.
	Name string
	// Aliases are alternative names for the command. They must be lowercase.
	Aliases []string
}

// UnknownCommandName is the name of the fallback handler which is used if no other handler is found.
// If even the unknown command handler is not found, the command is ignored.
const UnknownCommandName = "unknown-command"

func NewProcessor[MetaType any](cli *mautrix.Client) *Processor[MetaType] {
	proc := &Processor[MetaType]{
		Client:       cli,
		PreValidator: ValidatePrefixSubstring[MetaType]("!"),
		commands:     make(map[string]*Handler[MetaType]),
		aliases:      make(map[string]string),
	}
	proc.Register(&Handler[MetaType]{
		Name: UnknownCommandName,
		Func: func(ce *Event[MetaType]) {
			ce.Reply("Unknown command")
		},
	})
	return proc
}

// Register registers the given command handlers.
func (proc *Processor[MetaType]) Register(handlers ...*Handler[MetaType]) {
	proc.lock.Lock()
	defer proc.lock.Unlock()
	for _, handler := range handlers {
		proc.registerOne(handler)
	}
}

func (proc *Processor[MetaType]) registerOne(handler *Handler[MetaType]) {
	if strings.ToLower(handler.Name) != handler.Name {
		panic(fmt.Errorf("command %q is not lowercase", handler.Name))
	}
	proc.commands[handler.Name] = handler
	for _, alias := range handler.Aliases {
		if strings.ToLower(alias) != alias {
			panic(fmt.Errorf("alias %q is not lowercase", alias))
		}
		proc.aliases[alias] = handler.Name
	}
}

func (proc *Processor[MetaType]) Unregister(handlers ...*Handler[MetaType]) {
	proc.lock.Lock()
	defer proc.lock.Unlock()
	for _, handler := range handlers {
		proc.unregisterOne(handler)
	}
}

func (proc *Processor[MetaType]) unregisterOne(handler *Handler[MetaType]) {
	delete(proc.commands, handler.Name)
	for _, alias := range handler.Aliases {
		if proc.aliases[alias] == handler.Name {
			delete(proc.aliases, alias)
		}
	}
}

func (proc *Processor[MetaType]) Process(ctx context.Context, evt *event.Event) {
	log := *zerolog.Ctx(ctx)
	defer func() {
		panicErr := recover()
		if panicErr != nil {
			logEvt := log.Error().
				Bytes(zerolog.ErrorStackFieldName, debug.Stack())
			if realErr, ok := panicErr.(error); ok {
				logEvt = logEvt.Err(realErr)
			} else {
				logEvt = logEvt.Any(zerolog.ErrorFieldName, panicErr)
			}
			logEvt.Msg("Panic in command handler")
			_, err := proc.Client.SendReaction(ctx, evt.RoomID, evt.ID, "💥")
			if err != nil {
				log.Err(err).Msg("Failed to send reaction after panic")
			}
		}
	}()
	parsed := ParseEvent[MetaType](ctx, evt)
	if !proc.PreValidator.Validate(parsed) {
		return
	}

	realCommand := parsed.Command
	proc.lock.RLock()
	alias, ok := proc.aliases[realCommand]
	if ok {
		realCommand = alias
	}
	handler, ok := proc.commands[realCommand]
	if !ok {
		handler, ok = proc.commands[UnknownCommandName]
	}
	proc.lock.RUnlock()
	if !ok {
		return
	}

	logWith := log.With().
		Str("command", realCommand).
		Stringer("sender", evt.Sender).
		Stringer("room_id", evt.RoomID)
	if proc.LogArgs {
		logWith = logWith.Strs("args", parsed.Args)
	}
	log = logWith.Logger()
	parsed.Ctx = log.WithContext(ctx)
	parsed.Handler = handler
	parsed.Proc = proc
	parsed.Meta = proc.Meta

	log.Debug().Msg("Processing command")
	handler.Func(parsed)
}
