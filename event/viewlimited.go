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

type BeeperViewLimitedUpdateEventContent struct {
	RelatesTo RelatesTo `json:"m.relates_to"`
	Count     int       `json:"count"`
}
