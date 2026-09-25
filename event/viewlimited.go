// Copyright (c) 2026 Killian Lelong
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import "encoding/json"

type BeeperViewLimitedMedia struct {
	Type  string          `json:"type"`
	Count int             `json:"count,omitempty"`
	Time  int64           `json:"time,omitempty"`
	Meta  json.RawMessage `json:"meta,omitempty"`
}

type BeeperViewLimitedMediaUpdateContent struct {
	Count     int       `json:"count"`
	RelatesTo RelatesTo `json:"m.relates_to"`
}

func (content *BeeperViewLimitedMediaUpdateContent) GetRelatesTo() *RelatesTo {
	return &content.RelatesTo
}

func (content *BeeperViewLimitedMediaUpdateContent) OptionalGetRelatesTo() *RelatesTo {
	return &content.RelatesTo
}

func (content *BeeperViewLimitedMediaUpdateContent) SetRelatesTo(rel *RelatesTo) {
	content.RelatesTo = *rel
}
