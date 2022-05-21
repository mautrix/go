// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package configupgrade

import (
	"fmt"
	"os"
	"path"

	"gopkg.in/yaml.v3"
)

type Upgrader interface {
	DoUpgrade(helper *Helper)
}

type SpacedUpgrader interface {
	Upgrader
	SpacedBlocks() [][]string
}

type BaseUpgrader interface {
	Upgrader
	GetBase() string
}

type StructUpgrader struct {
	SimpleUpgrader
	Blocks [][]string
	Base   string
}

func (su *StructUpgrader) SpacedBlocks() [][]string {
	return su.Blocks
}

func (su *StructUpgrader) GetBase() string {
	return su.Base
}

type SimpleUpgrader func(helper *Helper)

func (su SimpleUpgrader) DoUpgrade(helper *Helper) {
	su(helper)
}

func (helper *Helper) apply(upgrader Upgrader) {
	upgrader.DoUpgrade(helper)
	helper.addSpaces(upgrader)
}

func (helper *Helper) addSpaces(upgrader Upgrader) {
	spaced, ok := upgrader.(SpacedUpgrader)
	if ok {
		for _, spacePath := range spaced.SpacedBlocks() {
			helper.AddSpaceBeforeComment(spacePath...)
		}
	}
}

func Do(configPath string, save bool, upgrader BaseUpgrader, additional ...Upgrader) ([]byte, bool, error) {
	sourceData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read config: %w", err)
	}
	var base, cfg yaml.Node
	err = yaml.Unmarshal([]byte(upgrader.GetBase()), &base)
	if err != nil {
		return sourceData, false, fmt.Errorf("failed to unmarshal example config: %w", err)
	}
	err = yaml.Unmarshal(sourceData, &cfg)
	if err != nil {
		return sourceData, false, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	helper := NewHelper(&base, &cfg)
	helper.apply(upgrader)
	for _, add := range additional {
		helper.apply(add)
	}

	output, err := yaml.Marshal(&base)
	if err != nil {
		return sourceData, false, fmt.Errorf("failed to marshal updated config: %w", err)
	}
	if save {
		var tempFile *os.File
		tempFile, err = os.CreateTemp(path.Dir(configPath), "mautrix-config-*.yaml")
		if err != nil {
			return output, true, fmt.Errorf("failed to create temp file for writing config: %w", err)
		}
		_, err = tempFile.Write(output)
		if err != nil {
			_ = os.Remove(tempFile.Name())
			return output, true, fmt.Errorf("failed to write updated config to temp file: %w", err)
		}
		err = os.Rename(tempFile.Name(), configPath)
		if err != nil {
			_ = os.Remove(tempFile.Name())
			return output, true, fmt.Errorf("failed to override current config with temp file: %w", err)
		}
	}
	return output, true, nil
}
