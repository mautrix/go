// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package id

// A RoomID is a string starting with ! that references a specific room.
// https://matrix.org/docs/spec/appendices#room-ids-and-event-ids
type RoomID string

// A RoomAlias is a string starting with # that can be resolved into.
// https://matrix.org/docs/spec/appendices#room-aliases
type RoomAlias string

// An EventID is a string starting with $ that references a specific event.
//
// https://matrix.org/docs/spec/appendices#room-ids-and-event-ids
// https://matrix.org/docs/spec/rooms/v4#event-ids
type EventID string

// A DeviceID is an arbitrary string that references a specific device.
type DeviceID string

// A KeyID is a string usually formatted as <algorithm>:<device_id> that is used as the key in deviceid-key mappings.
type KeyID string

func (roomID RoomID) String() string {
	return string(roomID)
}

func (roomAlias RoomAlias) String() string {
	return string(roomAlias)
}

func (eventID EventID) String() string {
	return string(eventID)
}

func (deviceID DeviceID) String() string {
	return string(deviceID)
}

func (keyID KeyID) String() string {
	return string(keyID)
}
