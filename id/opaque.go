// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package id

// A RoomID is a string starting with ! that references a specific room.
type RoomID string
// A RoomAlias is a string starting with # that can be resolved into
type RoomAlias string
// An EventID is a string starting with $ that references a specific event.
type EventID string
// A DeviceID is an arbitrary string that references a specific device.
type DeviceID string
// A KeyID is a string usually formatted as <algorithm>:<device_id> that is used as the key in deviceid-key mappings.
type KeyID string