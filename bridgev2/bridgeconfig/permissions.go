// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"maunium.net/go/mautrix/id"
)

type Permissions struct {
	SendEvents   bool `yaml:"send_events"`
	Commands     bool `yaml:"commands"`
	Login        bool `yaml:"login"`
	DoublePuppet bool `yaml:"double_puppet"`
	Admin        bool `yaml:"admin"`
	ManageRelay  bool `yaml:"manage_relay"`
	MaxLogins    int  `yaml:"max_logins"`
}

type PermissionConfig map[string]*Permissions

func boolToInt(val bool) int {
	if val {
		return 1
	}
	return 0
}

func (pc PermissionConfig) IsConfigured() bool {
	_, hasWildcard := pc["*"]
	_, hasExampleDomain := pc["example.com"]
	_, hasExampleUser := pc["@admin:example.com"]
	exampleLen := boolToInt(hasWildcard) + boolToInt(hasExampleUser) + boolToInt(hasExampleDomain)
	if len(pc) <= exampleLen {
		return false
	}
	return true
}

func (pc PermissionConfig) Get(userID id.UserID) Permissions {
	if level, ok := pc[string(userID)]; ok {
		return *level
	} else if level, ok = pc[userID.Homeserver()]; len(userID.Homeserver()) > 0 && ok {
		return *level
	} else if level, ok = pc["*"]; ok {
		return *level
	} else {
		return PermissionLevelBlock
	}
}

var (
	PermissionLevelBlock    = Permissions{}
	PermissionLevelRelay    = Permissions{SendEvents: true}
	PermissionLevelCommands = Permissions{SendEvents: true, Commands: true, ManageRelay: true}
	PermissionLevelUser     = Permissions{SendEvents: true, Commands: true, ManageRelay: true, Login: true, DoublePuppet: true}
	PermissionLevelAdmin    = Permissions{SendEvents: true, Commands: true, ManageRelay: true, Login: true, DoublePuppet: true, Admin: true}
)

var namesToLevels = map[string]Permissions{
	"block":    PermissionLevelBlock,
	"relay":    PermissionLevelRelay,
	"commands": PermissionLevelCommands,
	"user":     PermissionLevelUser,
	"admin":    PermissionLevelAdmin,
}

var levelsToNames = map[Permissions]string{
	PermissionLevelBlock:    "block",
	PermissionLevelRelay:    "relay",
	PermissionLevelCommands: "commands",
	PermissionLevelUser:     "user",
	PermissionLevelAdmin:    "admin",
}

type umPerm Permissions

func (p *Permissions) UnmarshalYAML(perm *yaml.Node) error {
	switch perm.Tag {
	case "!!str":
		var ok bool
		*p, ok = namesToLevels[strings.ToLower(perm.Value)]
		if !ok {
			return fmt.Errorf("invalid permissions level %s", perm.Value)
		}
		return nil
	case "!!map":
		err := perm.Decode((*umPerm)(p))
		return err
	case "!!int":
		val, err := strconv.Atoi(perm.Value)
		if err != nil {
			return fmt.Errorf("invalid permissions level %s", perm.Value)
		}
		_, _ = fmt.Fprintln(os.Stderr, "Warning: config contains deprecated integer permission values")
		// Integer values are deprecated, so they're hardcoded
		if val < 5 {
			*p = PermissionLevelBlock
		} else if val < 10 {
			*p = PermissionLevelRelay
		} else if val < 100 {
			*p = PermissionLevelUser
		} else {
			*p = PermissionLevelAdmin
		}
		return nil
	default:
		return fmt.Errorf("invalid permissions type %s", perm.Tag)
	}
}

func (p *Permissions) MarshalYAML() (any, error) {
	if level, ok := levelsToNames[*p]; ok {
		return level, nil
	}
	return umPerm(*p), nil
}
