// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"fmt"
	"strings"
	"sync"
)

type CommandContainer[MetaType any] struct {
	commands map[string]*Handler[MetaType]
	aliases  map[string]string
	lock     sync.RWMutex
}

func NewCommandContainer[MetaType any]() *CommandContainer[MetaType] {
	return &CommandContainer[MetaType]{
		commands: make(map[string]*Handler[MetaType]),
		aliases:  make(map[string]string),
	}
}

// Register registers the given command handlers.
func (cont *CommandContainer[MetaType]) Register(handlers ...*Handler[MetaType]) {
	if cont == nil {
		return
	}
	cont.lock.Lock()
	defer cont.lock.Unlock()
	for _, handler := range handlers {
		cont.registerOne(handler)
	}
}

func (cont *CommandContainer[MetaType]) registerOne(handler *Handler[MetaType]) {
	if strings.ToLower(handler.Name) != handler.Name {
		panic(fmt.Errorf("command %q is not lowercase", handler.Name))
	} else if val, alreadyExists := cont.commands[handler.Name]; alreadyExists && val != handler {
		panic(fmt.Errorf("tried to register command %q, but it's already registered", handler.Name))
	} else if aliasTarget, alreadyExists := cont.aliases[handler.Name]; alreadyExists {
		panic(fmt.Errorf("tried to register command %q, but it's already registered as an alias for %q", handler.Name, aliasTarget))
	}
	cont.commands[handler.Name] = handler
	for _, alias := range handler.Aliases {
		if strings.ToLower(alias) != alias {
			panic(fmt.Errorf("alias %q is not lowercase", alias))
		} else if val, alreadyExists := cont.aliases[alias]; alreadyExists && val != handler.Name {
			panic(fmt.Errorf("tried to register alias %q for %q, but it's already registered for %q", alias, handler.Name, cont.aliases[alias]))
		} else if _, alreadyExists = cont.commands[alias]; alreadyExists {
			panic(fmt.Errorf("tried to register alias %q for %q, but it's already registered as a command", alias, handler.Name))
		}
		cont.aliases[alias] = handler.Name
	}
	handler.initSubcommandContainer()
}

func (cont *CommandContainer[MetaType]) Unregister(handlers ...*Handler[MetaType]) {
	if cont == nil {
		return
	}
	cont.lock.Lock()
	defer cont.lock.Unlock()
	for _, handler := range handlers {
		cont.unregisterOne(handler)
	}
}

func (cont *CommandContainer[MetaType]) unregisterOne(handler *Handler[MetaType]) {
	delete(cont.commands, handler.Name)
	for _, alias := range handler.Aliases {
		if cont.aliases[alias] == handler.Name {
			delete(cont.aliases, alias)
		}
	}
}

func (cont *CommandContainer[MetaType]) GetHandler(name string) *Handler[MetaType] {
	if cont == nil {
		return nil
	}
	cont.lock.RLock()
	defer cont.lock.RUnlock()
	alias, ok := cont.aliases[name]
	if ok {
		name = alias
	}
	handler, ok := cont.commands[name]
	if !ok {
		handler = cont.commands[UnknownCommandName]
	}
	return handler
}
