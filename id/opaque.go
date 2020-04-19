// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package id

import (
	"fmt"
)

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

// A DeviceKeyID is a string formatted as <algorithm>:<device_id> that is used as the key in deviceid-key mappings.
type DeviceKeyID string

func NewDeviceKeyID(algorithm string, deviceID DeviceID) DeviceKeyID {
	return DeviceKeyID(fmt.Sprintf("%s:%s", algorithm, deviceID))
}

// A KeyID a string formatted as <algorithm>:<key_id> that is used as the key in one-time-key mappings.
type KeyID string

func NewKeyID(algorithm, keyID string) KeyID {
	return KeyID(fmt.Sprintf("%s:%s", algorithm, keyID))
}

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

func (keyID DeviceKeyID) String() string {
	return string(keyID)
}
