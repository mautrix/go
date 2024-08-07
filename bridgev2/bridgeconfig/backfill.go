// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

type BackfillConfig struct {
	Enabled              bool `yaml:"enabled"`
	MaxInitialMessages   int  `yaml:"max_initial_messages"`
	MaxCatchupMessages   int  `yaml:"max_catchup_messages"`
	UnreadHoursThreshold int  `yaml:"unread_hours_threshold"`

	Threads BackfillThreadsConfig `yaml:"threads"`
	Queue   BackfillQueueConfig   `yaml:"queue"`
}

type BackfillThreadsConfig struct {
	MaxInitialMessages int `yaml:"max_initial_messages"`
}

type BackfillQueueConfig struct {
	Enabled    bool `yaml:"enabled"`
	BatchSize  int  `yaml:"batch_size"`
	BatchDelay int  `yaml:"batch_delay"`
	MaxBatches int  `yaml:"max_batches"`

	MaxBatchesOverride map[string]int `yaml:"max_batches_override"`
}

func (bqc *BackfillQueueConfig) GetOverride(name string) int {
	override, ok := bqc.MaxBatchesOverride[name]
	if !ok {
		return bqc.MaxBatches
	}
	return override
}
