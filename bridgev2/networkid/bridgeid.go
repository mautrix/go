// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package networkid

// BridgeID is an opaque identifier for a bridge
type BridgeID string

// PortalID is the ID of a room on the remote network.
//
// Portal IDs must be globally unique and refer to a single chat.
// This means that user IDs can't be used directly as DM chat IDs, instead the ID must contain both user IDs (e.g. "user1-user2").
// If generating such IDs manually, sorting the users is recommended to ensure they're consistent.
type PortalID string

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
