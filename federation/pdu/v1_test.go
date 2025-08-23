// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu_test

import (
	"encoding/base64"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

var testV1PDUs = []testPDU{{
	name:          "m.room.message in v1 room",
	pdu:           `{"auth_events":[["$159234730483190eXavq:matrix.org",{"sha256":"VprZrhMqOQyKbfF3UE26JXE8D27ih4R/FGGc8GZ0Whs"}],["$143454825711DhCxH:matrix.org",{"sha256":"3sJh/5GOB094OKuhbjL634Gt69YIcge9GD55ciJa9ok"}],["$156837651426789wiPdh:maunium.net",{"sha256":"FGyR3sxJ/VxYabDkO/5qtwrPR3hLwGknJ0KX0w3GUHE"}]],"content":{"body":"photo-1526336024174-e58f5cdd8e13.jpg","info":{"h":1620,"mimetype":"image/jpeg","size":208053,"w":1080},"msgtype":"m.image","url":"mxc://maunium.net/aEqEghIjFPAerIhCxJCYpQeC"},"depth":16669,"event_id":"$16738169022163bokdi:maunium.net","hashes":{"sha256":"XYB47Gf2vAci3BTguIJaC75ZYGMuVY65jcvoUVgpcLA"},"origin":"maunium.net","origin_server_ts":1673816902100,"prev_events":[["$1673816901121325UMCjA:matrix.org",{"sha256":"t7e0IYHLI3ydIPoIU8a8E/pIWXH9cNLlQBEtGyGtHwc"}]],"room_id":"!jhpZBTbckszblMYjMK:matrix.org","sender":"@cat:maunium.net","type":"m.room.message","signatures":{"maunium.net":{"ed25519:a_xxeS":"uRZbEm+P+Y1ZVgwBn5I6SlaUZdzlH1bB4nv81yt5EIQ0b1fZ8YgM4UWMijrrXp3+NmqRFl0cakSM3MneJOtFCw"}},"unsigned":{"age_ts":1673816902100}}`,
	eventID:       "$16738169022163bokdi:maunium.net",
	roomVersion:   id.RoomV1,
	serverDetails: mauniumNet,
}, {
	name:          "m.room.create in v1 room",
	pdu:           `{"origin": "matrix.org", "signatures": {"matrix.org": {"ed25519:auto": "XTejpXn5REoHrZWgCpJglGX7MfOWS2zUjYwJRLrwW2PQPbFdqtL+JnprBXwIP2C1NmgWSKG+am1QdApu0KoHCQ"}}, "origin_server_ts": 1434548257426, "sender": "@appservice-irc:matrix.org", "event_id": "$143454825711DhCxH:matrix.org", "prev_events": [], "unsigned": {"age": 12872287834}, "state_key": "", "content": {"creator": "@appservice-irc:matrix.org"}, "depth": 1, "prev_state": [], "room_id": "!jhpZBTbckszblMYjMK:matrix.org", "auth_events": [], "hashes": {"sha256": "+SSdmeeoKI/6yK6sY4XAFljWFiugSlCiXQf0QMCZjTs"}, "type": "m.room.create"}`,
	eventID:       "$143454825711DhCxH:matrix.org",
	roomVersion:   id.RoomV1,
	serverDetails: matrixOrg,
}, {
	name:          "m.room.member in v1 room",
	pdu:           `{"auth_events": [["$1536447669931522zlyWe:matrix.org", {"sha256": "UkzPGd7cPAGvC0FVx3Yy2/Q0GZhA2kcgj8MGp5pjYV8"}], ["$143454825711DhCxH:matrix.org", {"sha256": "3sJh/5GOB094OKuhbjL634Gt69YIcge9GD55ciJa9ok"}], ["$143454825714nUEqZ:matrix.org", {"sha256": "NjuZXu8EDMfIfejPcNlC/IdnKQAGpPIcQjHaf0BZaHk"}]], "prev_events": [["$15660585503271JRRMm:maunium.net", {"sha256": "/Sm7uSLkYMHapp6I3NuEVJlk2JucW2HqjsQy9vzhciA"}]], "type": "m.room.member", "room_id": "!jhpZBTbckszblMYjMK:matrix.org", "sender": "@tulir:maunium.net", "content": {"membership": "join", "avatar_url": "mxc://maunium.net/jdlSfvudiMSmcRrleeiYjjFO", "displayname": "tulir"}, "depth": 10485, "prev_state": [], "state_key": "@tulir:maunium.net", "event_id": "$15660585693272iEryv:maunium.net", "origin": "maunium.net", "origin_server_ts": 1566058569201, "hashes": {"sha256": "1D6fdDzKsMGCxSqlXPA7I9wGQNTutVuJke1enGHoWK8"}, "signatures": {"maunium.net": {"ed25519:a_xxeS": "Lj/zDK6ozr4vgsxyL8jY56wTGWoA4jnlvkTs5paCX1w3nNKHnQnSMi+wuaqI6yv5vYh9usGWco2LLMuMzYXcBg"}}, "unsigned": {"age_ts": 1566058569201, "replaces_state": "$15660585383268liyBc:maunium.net"}}`,
	eventID:       "$15660585693272iEryv:maunium.net",
	roomVersion:   id.RoomV1,
	serverDetails: mauniumNet,
}}

func parseV1PDU(pdu string) (out *pdu.RoomV1PDU) {
	exerrors.PanicIfNotNil(json.Unmarshal([]byte(pdu), &out))
	return
}

func TestRoomV1PDU_CalculateContentHash(t *testing.T) {
	for _, test := range testV1PDUs {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseV1PDU(test.pdu)
			contentHash := exerrors.Must(parsed.CalculateContentHash())
			assert.Equal(
				t,
				base64.RawStdEncoding.EncodeToString(parsed.Hashes.SHA256),
				base64.RawStdEncoding.EncodeToString(contentHash[:]),
			)
		})
	}
}

func TestRoomV1PDU_VerifyContentHash(t *testing.T) {
	for _, test := range testV1PDUs {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseV1PDU(test.pdu)
			assert.True(t, parsed.VerifyContentHash())
		})
	}
}

func TestRoomV1PDU_VerifySignature(t *testing.T) {
	for _, test := range testV1PDUs {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseV1PDU(test.pdu)
			err := parsed.VerifySignature(test.roomVersion, test.serverName, func(serverName string, keyID id.KeyID, _ time.Time) (id.SigningKey, time.Time, error) {
				key, ok := test.keys[keyID]
				if ok {
					return key.key, key.validUntilTS, nil
				}
				return "", time.Time{}, nil
			})
			assert.NoError(t, err)
		})
	}
}
