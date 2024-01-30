// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"strconv"
	"strings"

	"github.com/element-hq/mautrix-go/id"
)

type PermissionConfig map[string]PermissionLevel

type PermissionLevel int

const (
	PermissionLevelBlock PermissionLevel = 0
	PermissionLevelRelay PermissionLevel = 5
	PermissionLevelUser  PermissionLevel = 10
	PermissionLevelAdmin PermissionLevel = 100
)

var namesToLevels = map[string]PermissionLevel{
	"block": PermissionLevelBlock,
	"relay": PermissionLevelRelay,
	"user":  PermissionLevelUser,
	"admin": PermissionLevelAdmin,
}

func RegisterPermissionLevel(name string, level PermissionLevel) {
	namesToLevels[name] = level
}

func (pc *PermissionConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	rawPC := make(map[string]string)
	err := unmarshal(&rawPC)
	if err != nil {
		return err
	}

	if *pc == nil {
		*pc = make(map[string]PermissionLevel)
	}
	for key, value := range rawPC {
		level, ok := namesToLevels[strings.ToLower(value)]
		if ok {
			(*pc)[key] = level
		} else if val, err := strconv.Atoi(value); err == nil {
			(*pc)[key] = PermissionLevel(val)
		} else {
			(*pc)[key] = PermissionLevelBlock
		}
	}
	return nil
}

func (pc PermissionConfig) Get(userID id.UserID) PermissionLevel {
	if level, ok := pc[string(userID)]; ok {
		return level
	} else if level, ok = pc[userID.Homeserver()]; len(userID.Homeserver()) > 0 && ok {
		return level
	} else if level, ok = pc["*"]; ok {
		return level
	} else {
		return PermissionLevelBlock
	}
}
