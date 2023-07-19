// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"sync"

	"maunium.net/go/mautrix/id"
)

// PowerLevelsEventContent represents the content of a m.room.power_levels state event content.
// https://spec.matrix.org/v1.5/client-server-api/#mroompower_levels
type PowerLevelsEventContent struct {
	usersLock    sync.RWMutex
	Users        map[id.UserID]int `json:"users,omitempty"`
	UsersDefault int               `json:"users_default,omitempty"`

	eventsLock    sync.RWMutex
	Events        map[string]int `json:"events,omitempty"`
	EventsDefault int            `json:"events_default,omitempty"`

	Notifications *NotificationPowerLevels `json:"notifications,omitempty"`

	StateDefaultPtr *int `json:"state_default,omitempty"`

	InvitePtr *int `json:"invite,omitempty"`
	KickPtr   *int `json:"kick,omitempty"`
	BanPtr    *int `json:"ban,omitempty"`
	RedactPtr *int `json:"redact,omitempty"`
}

func copyPtr(ptr *int) *int {
	if ptr == nil {
		return nil
	}
	val := *ptr
	return &val
}

func copyMap[Key comparable](m map[Key]int) map[Key]int {
	if m == nil {
		return nil
	}
	copied := make(map[Key]int, len(m))
	for k, v := range m {
		copied[k] = v
	}
	return copied
}

func (pl *PowerLevelsEventContent) Clone() *PowerLevelsEventContent {
	if pl == nil {
		return nil
	}
	return &PowerLevelsEventContent{
		Users:           copyMap(pl.Users),
		UsersDefault:    pl.UsersDefault,
		Events:          copyMap(pl.Events),
		EventsDefault:   pl.EventsDefault,
		StateDefaultPtr: copyPtr(pl.StateDefaultPtr),

		Notifications: pl.Notifications.Clone(),

		InvitePtr: copyPtr(pl.InvitePtr),
		KickPtr:   copyPtr(pl.KickPtr),
		BanPtr:    copyPtr(pl.BanPtr),
		RedactPtr: copyPtr(pl.RedactPtr),
	}
}

type NotificationPowerLevels struct {
	RoomPtr *int `json:"room,omitempty"`
}

func (npl *NotificationPowerLevels) Clone() *NotificationPowerLevels {
	if npl == nil {
		return nil
	}
	return &NotificationPowerLevels{
		RoomPtr: copyPtr(npl.RoomPtr),
	}
}

func (npl *NotificationPowerLevels) Room() int {
	if npl != nil && npl.RoomPtr != nil {
		return *npl.RoomPtr
	}
	return 50
}

func (pl *PowerLevelsEventContent) Invite() int {
	if pl.InvitePtr != nil {
		return *pl.InvitePtr
	}
	return 50
}

func (pl *PowerLevelsEventContent) Kick() int {
	if pl.KickPtr != nil {
		return *pl.KickPtr
	}
	return 50
}

func (pl *PowerLevelsEventContent) Ban() int {
	if pl.BanPtr != nil {
		return *pl.BanPtr
	}
	return 50
}

func (pl *PowerLevelsEventContent) Redact() int {
	if pl.RedactPtr != nil {
		return *pl.RedactPtr
	}
	return 50
}

func (pl *PowerLevelsEventContent) StateDefault() int {
	if pl.StateDefaultPtr != nil {
		return *pl.StateDefaultPtr
	}
	return 50
}

func (pl *PowerLevelsEventContent) GetUserLevel(userID id.UserID) int {
	pl.usersLock.RLock()
	defer pl.usersLock.RUnlock()
	level, ok := pl.Users[userID]
	if !ok {
		return pl.UsersDefault
	}
	return level
}

func (pl *PowerLevelsEventContent) SetUserLevel(userID id.UserID, level int) {
	pl.usersLock.Lock()
	defer pl.usersLock.Unlock()
	if level == pl.UsersDefault {
		delete(pl.Users, userID)
	} else {
		pl.Users[userID] = level
	}
}

func (pl *PowerLevelsEventContent) EnsureUserLevel(userID id.UserID, level int) bool {
	existingLevel := pl.GetUserLevel(userID)
	if existingLevel != level {
		pl.SetUserLevel(userID, level)
		return true
	}
	return false
}

func (pl *PowerLevelsEventContent) GetEventLevel(eventType Type) int {
	pl.eventsLock.RLock()
	defer pl.eventsLock.RUnlock()
	level, ok := pl.Events[eventType.String()]
	if !ok {
		if eventType.IsState() {
			return pl.StateDefault()
		}
		return pl.EventsDefault
	}
	return level
}

func (pl *PowerLevelsEventContent) SetEventLevel(eventType Type, level int) {
	pl.eventsLock.Lock()
	defer pl.eventsLock.Unlock()
	if (eventType.IsState() && level == pl.StateDefault()) || (!eventType.IsState() && level == pl.EventsDefault) {
		delete(pl.Events, eventType.String())
	} else {
		pl.Events[eventType.String()] = level
	}
}

func (pl *PowerLevelsEventContent) EnsureEventLevel(eventType Type, level int) bool {
	existingLevel := pl.GetEventLevel(eventType)
	if existingLevel != level {
		pl.SetEventLevel(eventType, level)
		return true
	}
	return false
}
