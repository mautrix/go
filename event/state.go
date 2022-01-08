// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"maunium.net/go/mautrix/id"
)

// CanonicalAliasEventContent represents the content of a m.room.canonical_alias state event.
// https://matrix.org/docs/spec/client_server/r0.6.1#m-room-canonical-alias
type CanonicalAliasEventContent struct {
	Alias      id.RoomAlias   `json:"alias"`
	AltAliases []id.RoomAlias `json:"alt_aliases,omitempty"`
}

// RoomNameEventContent represents the content of a m.room.name state event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-name
type RoomNameEventContent struct {
	Name string `json:"name"`
}

// RoomAvatarEventContent represents the content of a m.room.avatar state event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-avatar
type RoomAvatarEventContent struct {
	URL id.ContentURI `json:"url"`
}

// ServerACLEventContent represents the content of a m.room.server_acl state event.
// https://spec.matrix.org/v1.1/client-server-api/#server-access-control-lists-acls-for-rooms
type ServerACLEventContent struct {
	Allow           []string `json:"allow,omitempty"`
	AllowIPLiterals bool     `json:"allow_ip_literals"`
	Deny            []string `json:"deny,omitempty"`
}

// TopicEventContent represents the content of a m.room.topic state event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-topic
type TopicEventContent struct {
	Topic string `json:"topic"`
}

// TombstoneEventContent represents the content of a m.room.tombstone state event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-tombstone
type TombstoneEventContent struct {
	Body            string    `json:"body"`
	ReplacementRoom id.RoomID `json:"replacement_room"`
}

// CreateEventContent represents the content of a m.room.create state event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-create
type CreateEventContent struct {
	Type        RoomType  `json:"type,omitempty"`
	Creator     id.UserID `json:"creator,omitempty"`
	Federate    bool      `json:"m.federate,omitempty"`
	RoomVersion string    `json:"version,omitempty"`
	Predecessor struct {
		RoomID  id.RoomID  `json:"room_id"`
		EventID id.EventID `json:"event_id"`
	} `json:"predecessor"`
}

// JoinRule specifies how open a room is to new members.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-join-rules
type JoinRule string

const (
	JoinRulePublic  JoinRule = "public"
	JoinRuleKnock   JoinRule = "knock"
	JoinRuleInvite  JoinRule = "invite"
	JoinRulePrivate JoinRule = "private"
)

// JoinRulesEventContent represents the content of a m.room.join_rules state event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-join-rules
type JoinRulesEventContent struct {
	JoinRule JoinRule `json:"join_rule"`
}

// PinnedEventsEventContent represents the content of a m.room.pinned_events state event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-pinned-events
type PinnedEventsEventContent struct {
	Pinned []id.EventID `json:"pinned"`
}

// HistoryVisibility specifies who can see new messages.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-history-visibility
type HistoryVisibility string

const (
	HistoryVisibilityInvited       HistoryVisibility = "invited"
	HistoryVisibilityJoined        HistoryVisibility = "joined"
	HistoryVisibilityShared        HistoryVisibility = "shared"
	HistoryVisibilityWorldReadable HistoryVisibility = "world_readable"
)

// HistoryVisibilityEventContent represents the content of a m.room.history_visibility state event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-history-visibility
type HistoryVisibilityEventContent struct {
	HistoryVisibility HistoryVisibility `json:"history_visibility"`
}

// GuestAccess specifies whether or not guest accounts can join.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-guest-access
type GuestAccess string

const (
	GuestAccessCanJoin   GuestAccess = "can_join"
	GuestAccessForbidden GuestAccess = "forbidden"
)

// GuestAccessEventContent represents the content of a m.room.guest_access state event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-guest-access
type GuestAccessEventContent struct {
	GuestAccess GuestAccess `json:"guest_access"`
}

type BridgeInfoSection struct {
	ID          string              `json:"id"`
	DisplayName string              `json:"displayname,omitempty"`
	AvatarURL   id.ContentURIString `json:"avatar_url,omitempty"`
	ExternalURL string              `json:"external_url,omitempty"`
}

// BridgeEventContent represents the content of a m.bridge state event.
// https://github.com/matrix-org/matrix-doc/pull/2346
type BridgeEventContent struct {
	BridgeBot id.UserID          `json:"bridgebot"`
	Creator   id.UserID          `json:"creator,omitempty"`
	Protocol  BridgeInfoSection  `json:"protocol"`
	Network   *BridgeInfoSection `json:"network,omitempty"`
	Channel   BridgeInfoSection  `json:"channel"`
}

type SpaceChildEventContent struct {
	Via   []string `json:"via,omitempty"`
	Order string   `json:"order,omitempty"`
}

type SpaceParentEventContent struct {
	Via       []string `json:"via,omitempty"`
	Canonical bool     `json:"canonical,omitempty"`
}

// ModPolicyContent represents the content of a m.room.rule.user, m.room.rule.room, and m.room.rule.server state event.
// https://spec.matrix.org/v1.1/client-server-api/#moderation-policy-lists
type ModPolicyContent struct {
	Entity         string `json:"entity"`
	Reason         string `json:"reason"`
	Recommendation string `json:"recommendation"`
}
