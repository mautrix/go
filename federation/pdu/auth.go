// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu

import (
	"slices"

	"github.com/tidwall/gjson"
	"go.mau.fi/util/exgjson"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type StateKey struct {
	Type     string
	StateKey string
}

var thirdPartyInviteTokenPath = exgjson.Path("third_party_invite", "signed", "token")

type AuthEventSelection []StateKey

func (aes *AuthEventSelection) Add(evtType, stateKey string) {
	key := StateKey{Type: evtType, StateKey: stateKey}
	if !aes.Has(key) {
		*aes = append(*aes, key)
	}
}

func (aes *AuthEventSelection) Has(key StateKey) bool {
	return slices.Contains(*aes, key)
}

func (pdu *PDU) AuthEventSelection(roomVersion id.RoomVersion) (keys AuthEventSelection) {
	if pdu.Type == event.StateCreate.Type && pdu.StateKey != nil {
		return AuthEventSelection{}
	}
	keys = make(AuthEventSelection, 0, 3)
	if !roomVersion.RoomIDIsCreateEventID() {
		keys.Add(event.StateCreate.Type, "")
	}
	keys.Add(event.StatePowerLevels.Type, "")
	keys.Add(event.StateMember.Type, pdu.Sender.String())
	if pdu.Type == event.StateMember.Type && pdu.StateKey != nil {
		keys.Add(event.StateMember.Type, *pdu.StateKey)
		membership := event.Membership(gjson.GetBytes(pdu.Content, "membership").Str)
		if membership == event.MembershipJoin || membership == event.MembershipInvite || membership == event.MembershipKnock {
			keys.Add(event.StateJoinRules.Type, "")
		}
		if membership == event.MembershipInvite {
			thirdPartyInviteToken := gjson.GetBytes(pdu.Content, thirdPartyInviteTokenPath).Str
			if thirdPartyInviteToken != "" {
				keys.Add(event.StateThirdPartyInvite.Type, thirdPartyInviteToken)
			}
		}
		if membership == event.MembershipJoin && roomVersion.RestrictedJoins() {
			authorizedVia := gjson.GetBytes(pdu.Content, "authorised_via_users_server").Str
			if authorizedVia != "" {
				keys.Add(event.StateMember.Type, authorizedVia)
			}
		}
	}
	return
}
