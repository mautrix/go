// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"maunium.net/go/mautrix/id"
)

// TagEventContent represents the content of a m.typing ephemeral event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-typing
type TypingEventContent struct {
	UserIDs []id.UserID `json:"user_ids"`
}

// ReceiptEventContent represents the content of a m.receipt ephemeral event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-receipt
type ReceiptEventContent map[id.EventID]Receipts

type Receipts struct {
	Read map[id.UserID]ReadReceipt `json:"m.read"`
}

type ReadReceipt struct {
	Timestamp int64 `json:"ts"`
}

type Presence string

const (
	PresenceOnline      = "online"
	PresenceOffline     = "offline"
	PresenceUnavailable = "unavailable"
)

// PresenceEventContent represents the content of a m.presence ephemeral event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-presence
type PresenceEventContent struct {
	Presence        Presence            `json:"presence"`
	Displayname     string              `json:"displayname,omitempty"`
	AvatarURL       id.ContentURIString `json:"avatar_url,omitempty"`
	LastActiveAgo   int64               `json:"last_active_ago,omitempty"`
	CurrentlyActive bool                `json:"currently_active,omitempty"`
	StatusMessage   string              `json:"status_msg,omitempty"`
}
