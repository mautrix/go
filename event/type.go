// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/json"
	"fmt"
	"strings"
)

type TypeClass int

func (tc TypeClass) Name() string {
	switch tc {
	case MessageEventType:
		return "message"
	case StateEventType:
		return "state"
	case EphemeralEventType:
		return "ephemeral"
	case AccountDataEventType:
		return "account data"
	case ToDeviceEventType:
		return "to-device"
	default:
		return "unknown"
	}
}

const (
	// Normal message events
	MessageEventType TypeClass = iota
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
	Class TypeClass
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

func (et *Type) GuessClass() TypeClass {
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
	case ToDeviceRoomKey.Type, ToDeviceRoomKeyRequest.Type, ToDeviceForwardedRoomKey.Type, ToDeviceRoomKeyWithheld.Type:
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

func (et Type) UnmarshalText(data []byte) error {
	et.Type = string(data)
	et.Class = et.GuessClass()
	return nil
}

func (et Type) MarshalText() ([]byte, error) {
	return []byte(et.Type), nil
}

func (et *Type) String() string {
	return et.Type
}

func (et *Type) Repr() string {
	return fmt.Sprintf("%s (%s)", et.Type, et.Class.Name())
}

// State events
var (
	StateAliases           = Type{"m.room.aliases", StateEventType}
	StateCanonicalAlias    = Type{"m.room.canonical_alias", StateEventType}
	StateCreate            = Type{"m.room.create", StateEventType}
	StateJoinRules         = Type{"m.room.join_rules", StateEventType}
	StateHistoryVisibility = Type{"m.room.history_visibility", StateEventType}
	StateGuestAccess       = Type{"m.room.guest_access", StateEventType}
	StateMember            = Type{"m.room.member", StateEventType}
	StatePowerLevels       = Type{"m.room.power_levels", StateEventType}
	StateRoomName          = Type{"m.room.name", StateEventType}
	StateTopic             = Type{"m.room.topic", StateEventType}
	StateRoomAvatar        = Type{"m.room.avatar", StateEventType}
	StatePinnedEvents      = Type{"m.room.pinned_events", StateEventType}
	StateTombstone         = Type{"m.room.tombstone", StateEventType}
	StateEncryption        = Type{"m.room.encryption", StateEventType}
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
	AccountDataDirectChats     = Type{"m.direct", AccountDataEventType}
	AccountDataPushRules       = Type{"m.push_rules", AccountDataEventType}
	AccountDataRoomTags        = Type{"m.tag", AccountDataEventType}
	AccountDataFullyRead       = Type{"m.fully_read", AccountDataEventType}
	AccountDataIgnoredUserList = Type{"m.ignored_user_list", AccountDataEventType}
)

// Device-to-device events
var (
	ToDeviceRoomKey             = Type{"m.room_key", ToDeviceEventType}
	ToDeviceRoomKeyRequest      = Type{"m.room_key_request", ToDeviceEventType}
	ToDeviceForwardedRoomKey    = Type{"m.forwarded_room_key", ToDeviceEventType}
	ToDeviceEncrypted           = Type{"m.room.encrypted", ToDeviceEventType}
	ToDeviceRoomKeyWithheld     = Type{"m.room_key.withheld", ToDeviceEventType}
	ToDeviceVerificationRequest = Type{"m.key.verification.request", ToDeviceEventType}
	ToDeviceVerificationStart   = Type{"m.key.verification.start", ToDeviceEventType}
	ToDeviceVerificationAccept  = Type{"m.key.verification.accept", ToDeviceEventType}
	ToDeviceVerificationKey     = Type{"m.key.verification.key", ToDeviceEventType}
	ToDeviceVerificationMAC     = Type{"m.key.verification.mac", ToDeviceEventType}
	ToDeviceVerificationCancel  = Type{"m.key.verification.cancel", ToDeviceEventType}

	ToDeviceOrgMatrixRoomKeyWithheld = Type{"org.matrix.room_key.withheld", ToDeviceEventType}
)
