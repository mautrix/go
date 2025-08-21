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

func RedactContent(eventType string, content jsontext.Value, roomVersion id.RoomVersion) jsontext.Value {
	switch eventType {
	case "m.room.member":
		allowedPaths := []string{"membership"}
		if roomVersion.RestrictedJoinsFix() {
			allowedPaths = append(allowedPaths, "join_authorised_via_users_server")
		}
		if roomVersion.UpdatedRedactionRules() {
			allowedPaths = append(allowedPaths, exgjson.Path("third_party_invite", "signed"))
		}
		return filteredObject(content, allowedPaths...)
	case "m.room.create":
		if !roomVersion.UpdatedRedactionRules() {
			return filteredObject(content, "creator")
		}
		return content
	case "m.room.join_rules":
		if roomVersion.RestrictedJoins() {
			return filteredObject(content, "join_rule", "allow")
		}
		return filteredObject(content, "join_rule")
	case "m.room.power_levels":
		allowedKeys := []string{"ban", "events", "events_default", "kick", "redact", "state_default", "users", "users_default"}
		if roomVersion.UpdatedRedactionRules() {
			allowedKeys = append(allowedKeys, "invite")
		}
		return filteredObject(content, allowedKeys...)
	case "m.room.history_visibility":
		return filteredObject(content, "history_visibility")
	case "m.room.redaction":
		if roomVersion.RedactsInContent() {
			return filteredObject(content, "redacts")
		}
		return emptyObject
	case "m.room.aliases":
		if roomVersion.SpecialCasedAliasesAuth() {
			return filteredObject(content, "aliases")
		}
		return emptyObject
	default:
		return emptyObject
	}
}

func (pdu *PDU) Redact(roomVersion id.RoomVersion) *PDU {
	pdu.Unknown = nil
	pdu.Unsigned = nil
	if roomVersion.UpdatedRedactionRules() {
		pdu.DeprecatedPrevState = nil
		pdu.DeprecatedOrigin = nil
		pdu.DeprecatedMembership = nil
	}
	if pdu.Type != "m.room.redaction" || roomVersion.RedactsInContent() {
		pdu.Redacts = nil
	}
	pdu.Content = RedactContent(pdu.Type, pdu.Content, roomVersion)
	return pdu
}
