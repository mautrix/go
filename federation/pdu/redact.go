// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu

import (
	"encoding/json/jsontext"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.mau.fi/util/exgjson"
	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix/id"
)

func filteredObject(object jsontext.Value, allowedPaths ...string) jsontext.Value {
	filtered := jsontext.Value("{}")
	var err error
	for _, path := range allowedPaths {
		res := gjson.GetBytes(object, path)
		if res.Exists() {
			var raw jsontext.Value
			if res.Index > 0 {
				raw = object[res.Index : res.Index+len(res.Raw)]
			} else {
				raw = jsontext.Value(res.Raw)
			}
			filtered, err = sjson.SetRawBytes(filtered, path, raw)
			if err != nil {
				panic(err)
			}
		}
	}
	return filtered
}

func (pdu *PDU) Clone() *PDU {
	return ptr.Clone(pdu)
}

func (pdu *PDU) RedactForSignature(roomVersion id.RoomVersion) *PDU {
	pdu.Signatures = nil
	return pdu.Redact(roomVersion)
}

var emptyObject = jsontext.Value("{}")

func (pdu *PDU) Redact(roomVersion id.RoomVersion) *PDU {
	pdu.Unknown = nil
	pdu.Unsigned = nil
	if roomVersion.UpdatedRedactionRules() {
		pdu.DeprecatedPrevState = nil
		pdu.DeprecatedOrigin = nil
		pdu.DeprecatedMembership = nil
	}

	switch pdu.Type {
	case "m.room.member":
		allowedPaths := []string{"membership"}
		if roomVersion.RestrictedJoinsFix() {
			allowedPaths = append(allowedPaths, "join_authorised_via_users_server")
		}
		if roomVersion.UpdatedRedactionRules() {
			allowedPaths = append(allowedPaths, exgjson.Path("third_party_invite", "signed"))
		}
		pdu.Content = filteredObject(pdu.Content, allowedPaths...)
	case "m.room.create":
		if !roomVersion.UpdatedRedactionRules() {
			pdu.Content = filteredObject(pdu.Content, "creator")
		} // else: all fields are protected
	case "m.room.join_rules":
		if roomVersion.RestrictedJoins() {
			pdu.Content = filteredObject(pdu.Content, "join_rule", "allow")
		} else {
			pdu.Content = filteredObject(pdu.Content, "join_rule")
		}
	case "m.room.power_levels":
		allowedKeys := []string{"ban", "events", "events_default", "kick", "redact", "state_default", "users", "users_default"}
		if roomVersion.UpdatedRedactionRules() {
			allowedKeys = append(allowedKeys, "invite")
		}
		pdu.Content = filteredObject(pdu.Content, allowedKeys...)
	case "m.room.history_visibility":
		pdu.Content = filteredObject(pdu.Content, "history_visibility")
	case "m.room.redaction":
		if roomVersion.RedactsInContent() {
			pdu.Content = filteredObject(pdu.Content, "redacts")
			pdu.Redacts = nil
		} else {
			pdu.Content = emptyObject
		}
	case "m.room.aliases":
		if roomVersion.SpecialCasedAliasesAuth() {
			pdu.Content = filteredObject(pdu.Content, "aliases")
		} else {
			pdu.Content = emptyObject
		}
	default:
		pdu.Content = emptyObject
	}
	return pdu
}
