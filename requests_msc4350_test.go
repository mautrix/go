// Copyright (c) 2026 Jonathan Page (benmichael)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"encoding/json"
	"testing"

	"maunium.net/go/mautrix/id"
)

// TestDeviceKeys_MSC4350Roundtrip verifies that the MSC4350 impersonator
// field round-trips through JSON marshal/unmarshal, accessible via the
// typed MSC4350Impersonator pointer, with no duplication in Extra.
func TestDeviceKeys_MSC4350Roundtrip(t *testing.T) {
	original := DeviceKeys{
		UserID:     "@whatsapp_27:example.org",
		DeviceID:   "GHOSTDEV",
		Algorithms: []id.Algorithm{}, // empty per spec
		Keys:       KeyMap{},         // empty per spec
		Signatures: map[id.UserID]map[id.KeyID]string{
			"@whatsappbot:example.org": {
				"ed25519:BOTDEV": "<sig-from-bot-device>",
			},
		},
		MSC4350Impersonator: &ImpersonatorDevice{
			UserID:   "@whatsappbot:example.org",
			DeviceID: "BOTDEV",
			Algorithms: []id.Algorithm{
				"m.olm.v1.curve25519-aes-sha2",
				"m.megolm.v1.aes-sha2",
			},
			Keys: KeyMap{
				"curve25519:BOTDEV": "<bot-curve25519>",
				"ed25519:BOTDEV":    "<bot-ed25519>",
			},
		},
	}

	data, err := json.Marshal(&original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// The unstable prefix must appear in the serialized JSON, not the
	// stable name. If this fails, we shipped a violation of MSC4350's
	// "Unstable prefix" section.
	asMap := map[string]any{}
	if err := json.Unmarshal(data, &asMap); err != nil {
		t.Fatalf("re-unmarshal-as-map failed: %v", err)
	}
	if _, ok := asMap["fi.mau.msc4350.impersonator"]; !ok {
		t.Errorf("expected serialized JSON to contain unstable key %q, got %s",
			"fi.mau.msc4350.impersonator", string(data))
	}
	if _, ok := asMap["impersonator"]; ok {
		t.Errorf("serialized JSON must NOT contain stable %q key "+
			"until spec is accepted; got %s", "impersonator", string(data))
	}

	var roundTripped DeviceKeys
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if roundTripped.MSC4350Impersonator == nil {
		t.Fatal("expected MSC4350Impersonator to be populated after round-trip")
	}
	if got, want := roundTripped.MSC4350Impersonator.UserID, original.MSC4350Impersonator.UserID; got != want {
		t.Errorf("impersonator UserID: got %q, want %q", got, want)
	}
	if got, want := roundTripped.MSC4350Impersonator.DeviceID, original.MSC4350Impersonator.DeviceID; got != want {
		t.Errorf("impersonator DeviceID: got %q, want %q", got, want)
	}
	if got, want := len(roundTripped.MSC4350Impersonator.Algorithms), 2; got != want {
		t.Errorf("impersonator Algorithms count: got %d, want %d", got, want)
	}
	if _, ok := roundTripped.MSC4350Impersonator.Keys["ed25519:BOTDEV"]; !ok {
		t.Errorf("impersonator Keys missing ed25519:BOTDEV; got %v", roundTripped.MSC4350Impersonator.Keys)
	}

	// Extra must not contain a duplicate of the impersonator field —
	// that would cause double-encoding on the next marshal.
	if _, dup := roundTripped.Extra["fi.mau.msc4350.impersonator"]; dup {
		t.Error("Extra should not contain a duplicate of the impersonator field after unmarshal")
	}
}

// TestDeviceKeys_MSC4350Absent verifies the impersonator field is omitted
// from serialized JSON when not set, so we don't accidentally announce
// MSC4350 support for vanilla bridge bot devices.
func TestDeviceKeys_MSC4350Absent(t *testing.T) {
	dk := DeviceKeys{
		UserID:     "@whatsappbot:example.org",
		DeviceID:   "BOTDEV",
		Algorithms: []id.Algorithm{"m.olm.v1.curve25519-aes-sha2"},
		Keys: KeyMap{
			"curve25519:BOTDEV": "<curve>",
			"ed25519:BOTDEV":    "<ed>",
		},
		Signatures: map[id.UserID]map[id.KeyID]string{
			"@whatsappbot:example.org": {"ed25519:BOTDEV": "<sig>"},
		},
	}

	data, err := json.Marshal(&dk)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	asMap := map[string]any{}
	if err := json.Unmarshal(data, &asMap); err != nil {
		t.Fatalf("re-unmarshal-as-map failed: %v", err)
	}
	if _, present := asMap["fi.mau.msc4350.impersonator"]; present {
		t.Errorf("impersonator field must be omitted when nil; got %s", string(data))
	}
}

// TestDeviceKeys_MSC4350ExtraFieldsPreserved verifies that other unknown
// fields (which the bridge framework relies on via the Extra map) still
// flow through after the impersonator-field addition.
func TestDeviceKeys_MSC4350ExtraFieldsPreserved(t *testing.T) {
	input := []byte(`{
		"user_id": "@whatsapp_27:example.org",
		"device_id": "GHOSTDEV",
		"algorithms": [],
		"keys": {},
		"signatures": {},
		"fi.mau.msc4350.impersonator": {
			"user_id": "@whatsappbot:example.org",
			"device_id": "BOTDEV",
			"algorithms": ["m.olm.v1.curve25519-aes-sha2"],
			"keys": {"ed25519:BOTDEV": "<key>"}
		},
		"some.unknown.extension": {"hello": "world"}
	}`)

	var dk DeviceKeys
	if err := json.Unmarshal(input, &dk); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if dk.MSC4350Impersonator == nil {
		t.Fatal("expected MSC4350Impersonator to be populated")
	}
	if dk.Extra == nil || dk.Extra["some.unknown.extension"] == nil {
		t.Errorf("Extra map should contain unknown fields; got %#v", dk.Extra)
	}
	// Confirm we DON'T duplicate the typed field in Extra:
	if _, dup := dk.Extra["fi.mau.msc4350.impersonator"]; dup {
		t.Error("Extra must not contain a duplicate of the typed impersonator field")
	}
}
