// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu_test

import (
	"encoding/json/v2"
	"time"

	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

type serverKey struct {
	key          id.SigningKey
	validUntilTS time.Time
}

type serverDetails struct {
	serverName string
	keys       map[id.KeyID]serverKey
}

func (sd serverDetails) getKey(serverName string, keyID id.KeyID, _ time.Time) (id.SigningKey, time.Time, error) {
	if serverName != sd.serverName {
		return "", time.Time{}, nil
	}
	key, ok := sd.keys[keyID]
	if ok {
		return key.key, key.validUntilTS, nil
	}
	return "", time.Time{}, nil
}

var mauniumNet = serverDetails{
	serverName: "maunium.net",
	keys: map[id.KeyID]serverKey{
		"ed25519:a_xxeS": {
			key:          "lVt/CC3tv74OH6xTph2JrUmeRj/j+1q0HVa0Xf4QlCg",
			validUntilTS: time.Now(),
		},
	},
}
var envsNet = serverDetails{
	serverName: "envs.net",
	keys: map[id.KeyID]serverKey{
		"ed25519:a_zIqy": {
			key:          "vCUcZpt9hUn0aabfh/9GP/6sZvXcydww8DUstPHdJm0",
			validUntilTS: time.UnixMilli(1722360538068),
		},
		"ed25519:wuJyKT": {
			key:          "xbE1QssgomL4wCSlyMYF5/7KxVyM4HPwAbNa+nFFnx0",
			validUntilTS: time.Now(),
		},
	},
}
var matrixOrg = serverDetails{
	serverName: "matrix.org",
	keys: map[id.KeyID]serverKey{
		"ed25519:auto": {
			key:          "Noi6WqcDj0QmPxCNQqgezwTlBKrfqehY1u2FyWP9uYw",
			validUntilTS: time.UnixMilli(1576767829750),
		},
		"ed25519:a_RXGa": {
			key:          "l8Hft5qXKn1vfHrg3p4+W8gELQVo8N13JkluMfmn2sQ",
			validUntilTS: time.Now(),
		},
	},
}
var continuwuityOrg = serverDetails{
	serverName: "continuwuity.org",
	keys: map[id.KeyID]serverKey{
		"ed25519:PwHlNsFu": {
			key:          "8eNx2s0zWW+heKAmOH5zKv/nCPkEpraDJfGHxDu6hFI",
			validUntilTS: time.Now(),
		},
	},
}
var novaAstraltechOrg = serverDetails{
	serverName: "nova.astraltech.org",
	keys: map[id.KeyID]serverKey{
		"ed25519:a_afpo": {
			key:          "O1Y9GWuKo9xkuzuQef6gROxtTgxxAbS3WPNghPYXF3o",
			validUntilTS: time.Now(),
		},
	},
}

type testPDU struct {
	name        string
	pdu         string
	eventID     id.EventID
	roomVersion id.RoomVersion
	redacted    bool
	serverDetails
}

var roomV4MessageTestPDU = testPDU{
	name:          "m.room.message in v4 room",
	pdu:           `{"auth_events":["$OB87jNemaIVDHAfu0-pa_cP7OPFXUXCbFpjYVi8gll4","$RaWbTF9wQfGQgUpe1S13wzICtGTB2PNKRHUNHu9IO1c","$ZmEWOXw6cC4Rd1wTdY5OzeLJVzjhrkxFPwwKE4gguGk"],"content":{"body":"the last one is saying it shouldn't have effects","com.beeper.linkpreviews":[],"m.mentions":{},"msgtype":"m.text"},"depth":13103,"hashes":{"sha256":"c2wb8qMlvzIPCP1Wd+eYZ4BRgnGYxS97dR1UlJjVMeg"},"origin_server_ts":1752875275263,"prev_events":["$-7_BMI3BXwj3ayoxiJvraJxYWTKwjiQ6sh7CW_Brvj0"],"room_id":"!JiiOHXrIUCtcOJsZCa:matrix.org","sender":"@tulir:maunium.net","type":"m.room.message","signatures":{"maunium.net":{"ed25519:a_xxeS":"99TAqHpBkUEtgCraXsVXogmf/hnijPbgbG9eACtA+mbix3Y6gURI4QGQgcX/NhcE3pJQZ/YDjmbuvCnKvEccAA"}},"unsigned":{"age_ts":1752875275281}}`,
	eventID:       "$Jo_lmFR-e6lzrimzCA7DevIn2OwhuQYmd9xkcJBoqAA",
	roomVersion:   id.RoomV4,
	serverDetails: mauniumNet,
}

var roomV12MessageTestPDU = testPDU{
	name:          "m.room.message in v12 room",
	pdu:           `{"auth_events":["$gCzdJUVV93Qory0x7p_PLG5UUiDjPJNe1H12qbHTuFA","$hyeL_nU_L3tsZ2dtZZpAHk0Skv-PqFQIipuII_By584"],"content":{"body":"meow","com.beeper.linkpreviews":[],"m.mentions":{},"msgtype":"m.text"},"depth":122,"hashes":{"sha256":"IQ0zlc+PXeEs6R3JvRkW3xTPV3zlGKSSd3x07KXGjzs"},"origin_server_ts":1755384351627,"prev_events":["$gCzdJUVV93Qory0x7p_PLG5UUiDjPJNe1H12qbHTuFA"],"room_id":"!mauT12AzsoqxV7Abvy_ApA-HNPK1LcT4GbP70_AOPyQ","sender":"@tulir_test:maunium.net","type":"m.room.message","signatures":{"maunium.net":{"ed25519:a_xxeS":"0GDMddL2k7gF4V1VU8sL3wTfhAIzAu5iVH5jeavZ2VEg3J9/tHLWXAOn2tzkLaMRWl0/XpINT2YlH/rd2U21Ag"}},"unsigned":{"age_ts":1755384351627}}`,
	eventID:       "$xmP-wZfpannuHG-Akogi6c4YvqxChMtdyYbUMGOrMWc",
	roomVersion:   id.RoomV12,
	serverDetails: mauniumNet,
}

var testPDUs = []testPDU{roomV4MessageTestPDU, {
	name:          "m.room.message in v5 room",
	pdu:           `{"auth_events":["$hp0ImHqYgHTRbLeWKPeTeFmxdb5SdMJN9cfmTrTk7d0","$KAj7X7tnJbR9qYYMWJSw-1g414_KlPptbbkZm7_kUtg","$V-2ShOwZYhA_nxMijaf3lqFgIJgzE2UMeFPtOLnoBYM"],"content":{"body":"meow","com.beeper.linkpreviews":[],"m.mentions":{},"msgtype":"m.text"},"depth":2248,"hashes":{"sha256":"kV+JuLbWXJ2r6PjHT3wt8bFc/TfI1nTaSN3Lamg/xHs"},"origin_server_ts":1755422945654,"prev_events":["$49lFLem2Nk4dxHk9RDXxTdaq9InIJpmkHpzVnjKcYwg"],"room_id":"!vzBgJsjNzgHSdWsmki:mozilla.org","sender":"@tulir:maunium.net","type":"m.room.message","signatures":{"maunium.net":{"ed25519:a_xxeS":"JIl60uVgfCLBZLPoSiE7wVkJ9U5cNEPVPuv1sCCYUOq5yOW56WD1adgpBUdX2UFpYkCHvkRnyQGxU0+6HBp5BA"}},"unsigned":{"age_ts":1755422945673}}`,
	eventID:       "$Qn4tHfuAe6PlnKXPZnygAU9wd6RXqMKtt_ZzstHTSgA",
	roomVersion:   id.RoomV5,
	serverDetails: mauniumNet,
}, {
	name:          "m.room.message in v10 room",
	pdu:           `{"auth_events":["$--ilpwnsHaEdHrwiMrZNu5xHP6TthWG0FIXMHnlHCcs","$tn1FZUI_YUpfTr_a3Y_r8kC3inliIZZratzg0UsNdCQ","$Z-qMWmiMvm-aIEffcfSO6lN7TyjyTOsIcHIymfzoo20"],"content":{"body":"meow","com.beeper.linkpreviews":[],"m.mentions":{},"msgtype":"m.text"},"depth":100885,"hashes":{"sha256":"jc9272JPpPIVreJC3UEAm3BNVnLX8sm3U/TZs23wsHo"},"origin_server_ts":1755422792518,"prev_events":["$HDtbzpSys36Hk-F2NsiXfp9slsGXBH0b58qyddj_q5E"],"room_id":"!UzZHbJYcgggctGnlzr:envs.net","sender":"@tulir:maunium.net","type":"m.room.message","signatures":{"maunium.net":{"ed25519:a_xxeS":"sAMLo9jPtNB0Jq67IQm06siEBx82qZa2edu56IDQ4tDylEV4Mq7iFO23gCghqXA7B/MqBsjXotGBxv6AvlJ2Dw"}},"unsigned":{"age_ts":1755422792540}}`,
	eventID:       "$4ZFr_ypfp4DyZQP4zyxM_cvuOMFkl07doJmwi106YFY",
	roomVersion:   id.RoomV10,
	serverDetails: mauniumNet,
}, {
	name:          "m.room.message in v11 room",
	pdu:           `{"auth_events":["$L8Ak6A939llTRIsZrytMlLDXQhI4uLEjx-wb1zSg-Bw","$QJmr7mmGeXGD4Tof0ZYSPW2oRGklseyHTKtZXnF-YNM","$7bkKK_Z-cGQ6Ae4HXWGBwXyZi3YjC6rIcQzGfVyl3Eo"],"content":{"body":"meow","com.beeper.linkpreviews":[],"m.mentions":{},"msgtype":"m.text"},"depth":3212,"hashes":{"sha256":"K549YdTnv62Jn84Y7sS5ZN3+AdmhleZHbenbhUpR2R8"},"origin_server_ts":1754242687127,"prev_events":["$DAhJg4jVsqk5FRatE2hbT1dSA8D2ASy5DbjEHIMSHwY"],"room_id":"!offtopic-2:continuwuity.org","sender":"@tulir:maunium.net","type":"m.room.message","signatures":{"maunium.net":{"ed25519:a_xxeS":"SkzZdZ+rH22kzCBBIAErTdB0Vg6vkFmzvwjlOarGul72EnufgtE/tJcd3a8szAdK7f1ZovRyQxDgVm/Ib2u0Aw"}},"unsigned":{"age_ts":1754242687146}}`,
	eventID:       `$qkWfTL7_l3oRZO2CItW8-Q0yAmi_l_1ua629ZDqponE`,
	roomVersion:   id.RoomV11,
	serverDetails: mauniumNet,
}, roomV12MessageTestPDU, {
	name:          "m.room.create in v4 room",
	pdu:           `{"auth_events": [], "prev_events": [], "type": "m.room.create", "room_id": "!jxlRxnrZCsjpjDubDX:matrix.org", "sender": "@neilj:matrix.org", "content": {"room_version": "4", "predecessor": {"room_id": "!DYgXKezaHgMbiPMzjX:matrix.org", "event_id": "$156171636353XwPJT:matrix.org"}, "creator": "@neilj:matrix.org"}, "depth": 1, "prev_state": [], "state_key": "", "origin": "matrix.org", "origin_server_ts": 1561716363993, "hashes": {"sha256": "9tj8GpXjTAJvdNAbnuKLemZZk+Tjv2LAbGodSX6nJAo"}, "signatures": {"matrix.org": {"ed25519:auto": "2+sNt8uJUhzU4GPxnFVYtU2ZRgFdtVLT1vEZGUdJYN40zBpwYEGJy+kyb5matA+8/yLeYD9gu1O98lhleH0aCA"}}, "unsigned": {"age": 104769}}`,
	eventID:       "$ay_9_nPilrTpb3UxIwHHBBfFjTJb6hBAE_JzQwSjqeY",
	roomVersion:   id.RoomV4,
	serverDetails: matrixOrg,
}, {
	name:          "m.room.create in v10 room",
	pdu:           `{"auth_events":[],"content":{"creator":"@creme:envs.net","predecessor":{"event_id":"$BxYNisKcyBDhPLiVC06t18qhv7wsT72MzMCqn5vRhfY","room_id":"!tEyFYiMHhwJlDXTxwf:envs.net"},"room_version":"10"},"depth":1,"hashes":{"sha256":"us3TrsIjBWpwbm+k3F9fUVnz9GIuhnb+LcaY47fWwUI"},"origin":"envs.net","origin_server_ts":1664394769527,"prev_events":[],"room_id":"!UzZHbJYcgggctGnlzr:envs.net","sender":"@creme:envs.net","state_key":"","type":"m.room.create","signatures":{"envs.net":{"ed25519:a_zIqy":"0g3FDaD1e5BekJYW2sR7dgxuKoZshrf8P067c9+jmH6frsWr2Ua86Ax08CFa/n46L8uvV2SGofP8iiVYgXCRBg"}},"unsigned":{"age":2060}}`,
	eventID:       "$tn1FZUI_YUpfTr_a3Y_r8kC3inliIZZratzg0UsNdCQ",
	roomVersion:   id.RoomV10,
	serverDetails: envsNet,
}, {
	name:          "m.room.create in v12 room",
	pdu:           `{"auth_events":[],"content":{"fi.mau.randomness":"AAXZ6aIc","predecessor":{"room_id":"!#test/room\nversion <u>11</u>, with @\ud83d\udc08\ufe0f:maunium.net"},"room_version":"12"},"depth":1,"hashes":{"sha256":"d3L1M3KUdyIKWcShyW6grUoJ8GOjCdSIEvQrDVHSpE8"},"origin_server_ts":1754940000000,"prev_events":[],"sender":"@tulir:maunium.net","state_key":"","type":"m.room.create","signatures":{"maunium.net":{"ed25519:a_xxeS":"ebjIRpzToc82cjb/RGY+VUzZic0yeRZrjctgx0SUTJxkprXn3/i1KdiYULfl/aD0cUJ5eL8gLakOSk2glm+sBw"}},"unsigned":{"age_ts":1754939139045}}`,
	eventID:       "$mauT12AzsoqxV7Abvy_ApA-HNPK1LcT4GbP70_AOPyQ",
	roomVersion:   id.RoomV12,
	serverDetails: mauniumNet,
}, {
	name:          "m.room.member in v4 room",
	pdu:           `{"auth_events":["$ay_9_nPilrTpb3UxIwHHBBfFjTJb6hBAE_JzQwSjqeY","$jg2AgCfnwnjR-osoyM0lVYS21QrtfmZxhGO90PRkmO4","$wMGMP4Ucij2_d4h_fVDgIT2xooLZAgMcBruT9oo3Jio","$yyDgV8w0_e8qslmn0nh9OeSq_fO0zjpjTjSEdKFxDso"],"prev_events":["$zSjNuTXhUe3Rq6NpKD3sNyl8a_asMnBhGC5IbacHlJ4"],"type":"m.room.member","room_id":"!jxlRxnrZCsjpjDubDX:matrix.org","sender":"@tulir:maunium.net","content":{"membership":"join","displayname":"tulir","avatar_url":"mxc://maunium.net/jdlSfvudiMSmcRrleeiYjjFO","clicked \"send membership event with no changes\"":true},"depth":14370,"prev_state":[],"state_key":"@tulir:maunium.net","origin":"maunium.net","origin_server_ts":1600871136259,"hashes":{"sha256":"Ga6bG9Mk0887ruzM9TAAfa1O3DbNssb+qSFtE9oeRL4"},"signatures":{"maunium.net":{"ed25519:a_xxeS":"fzOyDG3G3pEzixtWPttkRA1DfnHETiKbiG8SEBQe2qycQbZWPky7xX8WujSrUJH/+bxTABpQwEH49d+RakxtBw"}},"unsigned":{"age_ts":1600871136259,"replaces_state":"$jg2AgCfnwnjR-osoyM0lVYS21QrtfmZxhGO90PRkmO4"}}`,
	eventID:       "$VtuCNOfAWGow-cxy0ajeK3fvONcC8QzF2yWa43g0Gwo",
	roomVersion:   id.RoomV4,
	serverDetails: mauniumNet,
}, {
	name:          "m.room.member in v10 room",
	pdu:           `{"auth_events":["$HQC4hWaioLKVbMH94qKbfb3UnL4ocql2vi-VdUYI48I","$R9FUDgNAp9ms7b6ASunZOIkpqmsIRq_ROrNEznu62fs","$kEPF8Aj87EzRmFPriu2zdyEY0rY15XSqywTYVLUUlCA","$tn1FZUI_YUpfTr_a3Y_r8kC3inliIZZratzg0UsNdCQ"],"content":{"avatar_url":"mxc://maunium.net/jdlSfvudiMSmcRrleeiYjjFO","displayname":"tulir","membership":"join"},"depth":182,"hashes":{"sha256":"0HscBc921QV2dxK2qY7qrnyoAgfxBM7kKvqAXlEk+GE"},"origin":"maunium.net","origin_server_ts":1665402609039,"prev_events":["$R9FUDgNAp9ms7b6ASunZOIkpqmsIRq_ROrNEznu62fs"],"room_id":"!UzZHbJYcgggctGnlzr:envs.net","sender":"@tulir:maunium.net","state_key":"@tulir:maunium.net","type":"m.room.member","signatures":{"maunium.net":{"ed25519:a_xxeS":"lkOW0FSJ8MJ0wZpdwLH1Uf6FSl2q9/u6KthRIlM0CwHDJG4sIZ9DrMA8BdU8L/PWoDS/CoDUlLanDh99SplgBw"}},"unsigned":{"age_ts":1665402609039,"replaces_state":"$R9FUDgNAp9ms7b6ASunZOIkpqmsIRq_ROrNEznu62fs"}}`,
	eventID:       "$--ilpwnsHaEdHrwiMrZNu5xHP6TthWG0FIXMHnlHCcs",
	roomVersion:   id.RoomV10,
	serverDetails: mauniumNet,
}, {
	name:          "m.room.member of creator in v12 room",
	pdu:           `{"auth_events":[],"content":{"avatar_url":"mxc://maunium.net/jdlSfvudiMSmcRrleeiYjjFO","displayname":"tulir","membership":"join"},"depth":2,"hashes":{"sha256":"IebdOBYaaWYIx2zq/lkVCnjWIXTLk1g+vgFpJMgd2/E"},"origin_server_ts":1754939139117,"prev_events":["$mauT12AzsoqxV7Abvy_ApA-HNPK1LcT4GbP70_AOPyQ"],"room_id":"!mauT12AzsoqxV7Abvy_ApA-HNPK1LcT4GbP70_AOPyQ","sender":"@tulir:maunium.net","state_key":"@tulir:maunium.net","type":"m.room.member","signatures":{"maunium.net":{"ed25519:a_xxeS":"rFCgF2hmavdm6+P6/f7rmuOdoSOmELFaH3JdWjgBLZXS2z51Ma7fa2v2+BkAH1FvBo9FLhvEoFVM4WbNQLXtAA"}},"unsigned":{"age_ts":1754939139117}}`,
	eventID:       "$accqGxfvhBvMP4Sf6P7t3WgnaJK6UbonO2ZmwqSE5Sg",
	roomVersion:   id.RoomV12,
	serverDetails: mauniumNet,
}, {
	name:          "custom message event in v4 room",
	pdu:           `{"auth_events":["$VtuCNOfAWGow-cxy0ajeK3fvONcC8QzF2yWa43g0Gwo","$ay_9_nPilrTpb3UxIwHHBBfFjTJb6hBAE_JzQwSjqeY","$Gau_XwziYsr-rt3SouhbKN14twgmbKjcZZc_hz-nOgU"],"content":{"\ud83d\udc08\ufe0f":true,"\ud83d\udc15\ufe0f":false},"depth":69645,"hashes":{"sha256":"VHtWyCt+15ZesNnStU3FOkxrjzHJYZfd3JUgO9JWe0s"},"origin_server_ts":1755423939146,"prev_events":["$exmp4cj0OKOFSxuqBYiOYwQi5j_0XRc78d6EavAkhy0"],"room_id":"!jxlRxnrZCsjpjDubDX:matrix.org","sender":"@tulir:maunium.net","type":"\ud83d\udc08\ufe0f","signatures":{"maunium.net":{"ed25519:a_xxeS":"wfmP1XN4JBkKVkqrQnwysyEUslXt8hQRFwN9NC9vJaIeDMd0OJ6uqCas75808DuG71p23fzqbzhRnHckst6FCQ"}},"unsigned":{"age_ts":1755423939164}}`,
	eventID:       "$kAagtZAIEeZaLVCUSl74tAxQbdKbE22GU7FM-iAJBc0",
	roomVersion:   id.RoomV4,
	serverDetails: mauniumNet,
}, {
	name:          "redacted m.room.member event in v11 room with 2 signatures",
	pdu:           `{"auth_events":["$9f12-_stoY07BOTmyguE1QlqvghLBh9Rk6PWRLoZn_M","$IP8hyjBkIDREVadyv0fPCGAW9IXGNllaZyxqQwiY_tA","$7dN5J8EveliaPkX6_QSejl4GQtem4oieavgALMeWZyE"],"content":{"membership":"join"},"depth":96978,"hashes":{"sha256":"APYA/aj3u+P0EwNaEofuSIlfqY3cK3lBz6RkwHX+Zak"},"origin_server_ts":1755664164485,"prev_events":["$XBN9W5Ll8VEH3eYqJaemxCBTDdy0hZB0sWpmyoUp93c"],"room_id":"!main-1:continuwuity.org","sender":"@6a19abdd4766:nova.astraltech.org","state_key":"@6a19abdd4766:nova.astraltech.org","type":"m.room.member","signatures":{"continuwuity.org":{"ed25519:PwHlNsFu":"+b/Fp2vWnC+Z2lI3GnCu7ZHdo3iWNDZ2AJqMoU9owMtLBPMxs4dVIsJXvaFq0ryawsgwDwKZ7f4xaFUNARJSDg"},"nova.astraltech.org":{"ed25519:a_afpo":"pXIngyxKukCPR7WOIIy8FTZxQ5L2dLiou5Oc8XS4WyY4YzJuckQzOaToigLLZxamfbN/jXbO+XUizpRpYccDAA"}},"unsigned":{}}`,
	eventID:       "$r6d9m125YWG28-Tln47bWtm6Jlv4mcSUWJTHijBlXLQ",
	roomVersion:   id.RoomV11,
	serverDetails: novaAstraltechOrg,
	redacted:      true,
}}

func parsePDU(pdu string) (out *pdu.PDU) {
	exerrors.PanicIfNotNil(json.Unmarshal([]byte(pdu), &out))
	return
}
