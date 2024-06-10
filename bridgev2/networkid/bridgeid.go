// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package networkid

import (
	"fmt"

	"github.com/rs/zerolog"
)

// BridgeID is an opaque identifier for a bridge
type BridgeID string

// PortalID is the ID of a room on the remote network.
type PortalID string

// PortalKey is the unique key of a room on the remote network. It combines a portal ID and a receiver ID.
//
// The Receiver field is generally only used for DMs, and should be empty for group chats.
// The purpose is to segregate DMs by receiver, so that the same DM has separate rooms even
// if both sides are logged into the bridge. Also, for networks that use user IDs as DM chat IDs,
// the receiver is necessary to have separate rooms for separate users who have a DM with the same
// remote user.
type PortalKey struct {
	ID       PortalID
	Receiver UserLoginID
}

func (pk PortalKey) String() string {
	if pk.Receiver == "" {
		return string(pk.ID)
	}
	return fmt.Sprintf("%s/%s", pk.ID, pk.Receiver)
}

func (pk PortalKey) MarshalZerologObject(evt *zerolog.Event) {
	evt.Str("portal_id", string(pk.ID))
	if pk.Receiver != "" {
		evt.Str("portal_receiver", string(pk.Receiver))
	}
}

// UserID is the ID of a user on the remote network.
type UserID string

// UserLoginID is the ID of the user being controlled on the remote network. It may be the same shape as [UserID].
type UserLoginID string

// MessageID is the ID of a message on the remote network.
//
// Message IDs must be unique across rooms and consistent across users.
type MessageID string

// PartID is the ID of a message part on the remote network (e.g. index of image in album).
//
// Part IDs are only unique within a message, not globally.
// To refer to a specific message part globally, use the MessagePartID tuple struct.
type PartID string

// MessagePartID refers to a specific part of a message by combining a message ID and a part ID.
type MessagePartID struct {
	MessageID MessageID
	PartID    PartID
}

// MessageOptionalPartID refers to a specific part of a message by combining a message ID and an optional part ID.
// If the part ID is not set, this should refer to the first part ID sorted alphabetically.
type MessageOptionalPartID struct {
	MessageID MessageID
	PartID    *PartID
}

// AvatarID is the ID of a user or room avatar on the remote network.
//
// It may be a real URL, an opaque identifier, or anything in between.
type AvatarID string

// EmojiID is the ID of a reaction emoji on the remote network.
//
// On networks that only allow one reaction per message, an empty string should be used
// to apply the unique constraints in the database appropriately.
// On networks that allow multiple emojis, this is the unicode emoji or a network-specific shortcode.
type EmojiID string
