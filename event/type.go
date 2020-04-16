// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/json"
	"strings"
)

type EventTypeClass int

const (
	// Normal message events
	MessageEventType EventTypeClass = iota
	// State events
	StateEventType
	// Ephemeral events
	EphemeralEventType
	// Account data events
	AccountDataEventType
	// Device-to-device events
	ToDeviceEventType
	// Unknown events
	UnknownEventType
)

type Type struct {
	Type  string
	Class EventTypeClass
}

func NewEventType(name string) Type {
	evtType := Type{Type: name}
	evtType.Class = evtType.GuessClass()
	return evtType
}

func (et *Type) IsState() bool {
	return et.Class == StateEventType
}

func (et *Type) IsEphemeral() bool {
	return et.Class == EphemeralEventType
}

func (et *Type) IsAccountData() bool {
	return et.Class == AccountDataEventType
}

func (et *Type) IsToDevice() bool {
	return et.Class == ToDeviceEventType
}

func (et *Type) IsCustom() bool {
	return !strings.HasPrefix(et.Type, "m.")
}

func (et *Type) GuessClass() EventTypeClass {
	switch et.Type {
	case StateAliases.Type, StateCanonicalAlias.Type, StateCreate.Type, StateJoinRules.Type, StateMember.Type,
		StatePowerLevels.Type, StateRoomName.Type, StateRoomAvatar.Type, StateTopic.Type, StatePinnedEvents.Type,
		StateTombstone.Type, StateEncryption.Type:
		return StateEventType
	case EphemeralEventReceipt.Type, EphemeralEventTyping.Type, EphemeralEventPresence.Type:
		return EphemeralEventType
	case AccountDataDirectChats.Type, AccountDataPushRules.Type, AccountDataRoomTags.Type:
		return AccountDataEventType
	case EventRedaction.Type, EventMessage.Type, EventEncrypted.Type, EventReaction.Type, EventSticker.Type:
		return MessageEventType
	case ToDeviceNewDevice.Type, ToDeviceRoomKey.Type, ToDeviceRoomKeyRequest.Type, ToDeviceForwardedRoomKey.Type:
		return ToDeviceEventType
	default:
		return UnknownEventType
	}
}

func (et *Type) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &et.Type)
	if err != nil {
		return err
	}
	et.Class = et.GuessClass()
	return nil
}

func (et *Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(&et.Type)
}

func (et *Type) String() string {
	return et.Type
}

// State events
var (
	StateAliases        = Type{"m.room.aliases", StateEventType}
	StateCanonicalAlias = Type{"m.room.canonical_alias", StateEventType}
	StateCreate         = Type{"m.room.create", StateEventType}
	StateJoinRules      = Type{"m.room.join_rules", StateEventType}
	StateMember         = Type{"m.room.member", StateEventType}
	StatePowerLevels    = Type{"m.room.power_levels", StateEventType}
	StateRoomName       = Type{"m.room.name", StateEventType}
	StateTopic          = Type{"m.room.topic", StateEventType}
	StateRoomAvatar     = Type{"m.room.avatar", StateEventType}
	StatePinnedEvents   = Type{"m.room.pinned_events", StateEventType}
	StateTombstone      = Type{"m.room.tombstone", StateEventType}
	StateEncryption     = Type{"m.room.encryption", StateEventType}
)

// Message events
var (
	EventRedaction = Type{"m.room.redaction", MessageEventType}
	EventMessage   = Type{"m.room.message", MessageEventType}
	EventEncrypted = Type{"m.room.encrypted", MessageEventType}
	EventReaction  = Type{"m.reaction", MessageEventType}
	EventSticker   = Type{"m.sticker", MessageEventType}
)

// Ephemeral events
var (
	EphemeralEventReceipt  = Type{"m.receipt", EphemeralEventType}
	EphemeralEventTyping   = Type{"m.typing", EphemeralEventType}
	EphemeralEventPresence = Type{"m.presence", EphemeralEventType}
)

// Account data events
var (
	AccountDataDirectChats = Type{"m.direct", AccountDataEventType}
	AccountDataPushRules   = Type{"m.push_rules", AccountDataEventType}
	AccountDataRoomTags    = Type{"m.tag", AccountDataEventType}
)

// Device-to-device events
var (
	ToDeviceNewDevice = Type{"m.new_device", ToDeviceEventType}
	ToDeviceRoomKey = Type{"m.room_key", ToDeviceEventType}
	ToDeviceRoomKeyRequest = Type{"m.room_key_request", ToDeviceEventType}
	ToDeviceForwardedRoomKey = Type{"m.forwarded_room_key", ToDeviceEventType}
)
