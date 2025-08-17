// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu

import (
	"encoding/json/jsontext"

	"maunium.net/go/mautrix/id"
)

type RoomV1PDU struct {
	AuthEvents     [][]string                     `json:"auth_events"`
	Content        jsontext.Value                 `json:"content"`
	Depth          int64                          `json:"depth"`
	EventID        id.EventID                     `json:"event_id"`
	Hashes         *Hashes                        `json:"hashes,omitempty"`
	OriginServerTS int64                          `json:"origin_server_ts"`
	PrevEvents     [][]string                     `json:"prev_events"`
	Redacts        *id.EventID                    `json:"redacts,omitempty"`
	RoomID         id.RoomID                      `json:"room_id"`
	Sender         id.UserID                      `json:"sender"`
	Signatures     map[string]map[id.KeyID]string `json:"signatures,omitempty"`
	StateKey       *string                        `json:"state_key,omitempty"`
	Type           string                         `json:"type"`

	Unknown jsontext.Value `json:",unknown"`

	// Deprecated legacy fields
	DeprecatedPrevState  any `json:"prev_state,omitempty"`
	DeprecatedOrigin     any `json:"origin,omitempty"`
	DeprecatedMembership any `json:"membership,omitempty"`
}

func (pdu *RoomV1PDU) Redact() {
	pdu.Unknown = nil

	switch pdu.Type {
	case "m.room.member":
		pdu.Content = filteredObject(pdu.Content, "membership")
	case "m.room.create":
		pdu.Content = filteredObject(pdu.Content, "creator")
	case "m.room.join_rules":
		pdu.Content = filteredObject(pdu.Content, "join_rule")
	case "m.room.power_levels":
		pdu.Content = filteredObject(pdu.Content, "ban", "events", "events_default", "kick", "redact", "state_default", "users", "users_default")
	case "m.room.history_visibility":
		pdu.Content = filteredObject(pdu.Content, "history_visibility")
	case "m.room.aliases":
		pdu.Content = filteredObject(pdu.Content, "aliases")
	default:
		pdu.Content = jsontext.Value("{}")
	}
}
