// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/json/jsontext"
	"time"

	"go.mau.fi/util/jsontime"

	"maunium.net/go/mautrix/id"
)

// Event represents a single Matrix event.
type Event struct {
	StateKey  *string    `json:"state_key,omitzero"`        // The state key for the event. Only present on State Events.
	Sender    id.UserID  `json:"sender,omitempty"`          // The user ID of the sender of the event
	Type      Type       `json:"type"`                      // The event type
	Timestamp int64      `json:"origin_server_ts,omitzero"` // The unix timestamp when this message was sent by the origin server
	ID        id.EventID `json:"event_id,omitempty"`        // The unique ID of this event
	RoomID    id.RoomID  `json:"room_id,omitempty"`         // The room the event was sent to. May be nil (e.g. for presence)
	Content   Content    `json:"content"`                   // The JSON content of the event.
	Redacts   id.EventID `json:"redacts,omitempty"`         // The event ID that was redacted if a m.room.redaction event
	Unsigned  Unsigned   `json:"unsigned,omitzero"`         // Unsigned content set by own homeserver.

	Sticky *Sticky `json:"msc4354_sticky,omitzero"`

	Mautrix MautrixInfo `json:"-"`

	Unknown jsontext.Value `json:",embed,unknown"`

	ToUserID   id.UserID   `json:"to_user_id,omitempty"`   // The user ID that the to-device event was sent to. Only present in MSC2409 appservice transactions.
	ToDeviceID id.DeviceID `json:"to_device_id,omitempty"` // The device ID that the to-device event was sent to. Only present in MSC2409 appservice transactions.
}

type Sticky struct {
	Duration jsontime.Milliseconds `json:"duration_ms"`
}

const MaxStickyDuration = 1 * time.Hour

func (sticky *Sticky) GetDuration() time.Duration {
	if sticky != nil {
		return max(0, min(sticky.Duration.Duration, MaxStickyDuration))
	}
	return 0
}

func (evt *Event) GetStickyUntil() time.Time {
	if evt == nil || evt.Sticky.GetDuration() == 0 {
		return time.Time{}
	}
	return time.UnixMilli(evt.Timestamp).Add(evt.Sticky.GetDuration())
}

type MautrixInfo struct {
	EventSource Source

	TrustState    id.TrustState
	ForwardedKeys bool
	WasEncrypted  bool
	TrustSource   *id.Device

	ReceivedAt         time.Time
	EditedAt           time.Time
	LastEditID         id.EventID
	DecryptionDuration time.Duration

	CheckpointSent bool
	// When using MSC4222 and the state_after field, this field is set
	// for timeline events to indicate they shouldn't update room state.
	IgnoreState bool
}

func (evt *Event) GetStateKey() string {
	if evt.StateKey != nil {
		return *evt.StateKey
	}
	return ""
}

type Unsigned struct {
	PrevContent     *Content   `json:"prev_content,omitzero"`
	PrevSender      id.UserID  `json:"prev_sender,omitempty"`
	Membership      Membership `json:"membership,omitempty"`
	ReplacesState   id.EventID `json:"replaces_state,omitempty"`
	Age             int64      `json:"age,omitzero"`
	TransactionID   string     `json:"transaction_id,omitempty"`
	Relations       *Relations `json:"m.relations,omitzero"`
	RedactedBecause *Event     `json:"redacted_because,omitzero"`
	InviteRoomState []*Event   `json:"invite_room_state,omitempty"`

	StickyDurationTTL jsontime.Milliseconds `json:"msc4354_sticky_duration_ttl_ms,omitzero"`

	BeeperHSOrder       int64               `json:"com.beeper.hs.order,omitzero"`
	BeeperHSSuborder    int16               `json:"com.beeper.hs.suborder,omitzero"`
	BeeperHSOrderString *BeeperEncodedOrder `json:"com.beeper.hs.order_string,omitzero"`
	BeeperFromBackup    bool                `json:"com.beeper.from_backup,omitzero"`

	ElementSoftFailed         bool `json:"io.element.synapse.soft_failed,omitzero"`
	ElementPolicyServerSpammy bool `json:"io.element.synapse.policy_server_spammy,omitzero"`
}

func (us *Unsigned) IsZero() bool {
	return us == nil || us.IsEmpty()
}

func (us *Unsigned) IsEmpty() bool {
	return us.PrevContent == nil && us.PrevSender == "" && us.ReplacesState == "" && us.Age == 0 && us.Membership == "" &&
		us.TransactionID == "" && us.RedactedBecause == nil && us.InviteRoomState == nil && us.Relations == nil &&
		us.BeeperHSOrder == 0 && us.BeeperHSSuborder == 0 && us.BeeperHSOrderString.IsZero() &&
		!us.ElementSoftFailed && us.StickyDurationTTL.Duration == 0
}
