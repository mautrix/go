// Copyright (c) 2026 Jonathan Page (benmichael)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"encoding/json"
	"strings"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// recordingSigner is a deterministic ImpersonatorSigner that captures the
// object it was asked to sign and returns a fixed signature string. It
// lets us assert what was actually fed to SignJSON without depending on
// the goolm/libolm primitives, which require deps unavailable in some
// CI environments.
type recordingSigner struct {
	sigToReturn string
	lastSigned  any
	signErr     error
}

func (s *recordingSigner) SignJSON(obj any) (string, error) {
	s.lastSigned = obj
	if s.signErr != nil {
		return "", s.signErr
	}
	return s.sigToReturn, nil
}

const (
	testGhostUserID   id.UserID   = "@whatsapp_27733183724:matrix.thepages.family"
	testGhostDeviceID id.DeviceID = MSC4350ImpersonatableDeviceID
	testBotUserID     id.UserID   = "@whatsappbot:matrix.thepages.family"
	testBotDeviceID   id.DeviceID = "BOTDEV01"

	testBotSigningKey  id.SigningKey  = "QXFakeEd25519SigningKeyForTestPurposesOnly00"
	testBotIdentityKey id.IdentityKey = "QXFakeCurve25519IdentityKeyForTestPurposes00"
	testSignature                     = "BASE64ENCODEDFAKESIGNATUREVALUEFROMBOTDEV01"
)

// TestBuildImpersonatableDeviceKeys_Happy verifies the canonical happy
// path: result has the spec-required empty algorithms/keys, the typed
// impersonator field points at the bot, and the signature ends up keyed
// correctly under the bot's user/device.
func TestBuildImpersonatableDeviceKeys_Happy(t *testing.T) {
	signer := &recordingSigner{sigToReturn: testSignature}

	dk, err := BuildImpersonatableDeviceKeys(
		signer,
		testGhostUserID, testGhostDeviceID,
		testBotUserID, testBotDeviceID,
		testBotSigningKey, testBotIdentityKey,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dk.UserID != testGhostUserID {
		t.Errorf("UserID: got %q, want %q", dk.UserID, testGhostUserID)
	}
	if dk.DeviceID != testGhostDeviceID {
		t.Errorf("DeviceID: got %q, want %q", dk.DeviceID, testGhostDeviceID)
	}
	if len(dk.Algorithms) != 0 {
		t.Errorf("Algorithms MUST be empty per MSC4350, got %v", dk.Algorithms)
	}
	if len(dk.Keys) != 0 {
		t.Errorf("Keys MUST be empty per MSC4350, got %v", dk.Keys)
	}

	imp := dk.MSC4350Impersonator
	if imp == nil {
		t.Fatal("MSC4350Impersonator must be populated")
	}
	if imp.UserID != testBotUserID {
		t.Errorf("impersonator UserID: got %q, want %q", imp.UserID, testBotUserID)
	}
	if imp.DeviceID != testBotDeviceID {
		t.Errorf("impersonator DeviceID: got %q, want %q", imp.DeviceID, testBotDeviceID)
	}
	if len(imp.Algorithms) != 2 {
		t.Errorf("impersonator algorithms count: got %d, want 2", len(imp.Algorithms))
	}
	ed := imp.Keys[id.NewDeviceKeyID(id.KeyAlgorithmEd25519, testBotDeviceID)]
	if ed != string(testBotSigningKey) {
		t.Errorf("impersonator ed25519 key: got %q, want %q", ed, testBotSigningKey)
	}
	curve := imp.Keys[id.NewDeviceKeyID(id.KeyAlgorithmCurve25519, testBotDeviceID)]
	if curve != string(testBotIdentityKey) {
		t.Errorf("impersonator curve25519 key: got %q, want %q", curve, testBotIdentityKey)
	}

	// Signature: keyed by BOT user/device, NOT the ghost.
	keyID := id.NewKeyID(id.KeyAlgorithmEd25519, testBotDeviceID.String())
	gotSig, ok := dk.Signatures[testBotUserID][keyID]
	if !ok {
		t.Fatalf("expected signature under [%s][%s]; got Signatures=%#v",
			testBotUserID, keyID, dk.Signatures)
	}
	if gotSig != testSignature {
		t.Errorf("signature value: got %q, want %q", gotSig, testSignature)
	}
	if _, ghostSigned := dk.Signatures[testGhostUserID]; ghostSigned {
		t.Errorf("ghost user MUST NOT appear in signatures map; got %#v", dk.Signatures)
	}
}

// TestBuildImpersonatableDeviceKeys_SignedObjectIsCorrect verifies that
// the signer is invoked on the device keys BEFORE the signatures map is
// populated, so the signature is over a canonical form that does not
// already contain itself.
func TestBuildImpersonatableDeviceKeys_SignedObjectIsCorrect(t *testing.T) {
	signer := &recordingSigner{sigToReturn: testSignature}

	_, err := BuildImpersonatableDeviceKeys(
		signer,
		testGhostUserID, testGhostDeviceID,
		testBotUserID, testBotDeviceID,
		testBotSigningKey, testBotIdentityKey,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	signed, ok := signer.lastSigned.(*mautrix.DeviceKeys)
	if !ok {
		t.Fatalf("expected lastSigned to be *mautrix.DeviceKeys, got %T", signer.lastSigned)
	}
	if len(signed.Signatures) != 0 {
		t.Errorf("device handed to signer MUST have empty Signatures, got %#v", signed.Signatures)
	}

	// The marshalled JSON sent for signing must already carry the
	// impersonator field under its unstable prefix — otherwise the
	// signature wouldn't bind it.
	asJSON, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("re-marshal failed: %v", err)
	}
	if !strings.Contains(string(asJSON), `"fi.mau.msc4350.impersonator"`) {
		t.Errorf("signed JSON missing the impersonator field; got %s", string(asJSON))
	}
}

// TestBuildImpersonatableDeviceKeys_SignerError surfaces signer failures
// to the caller so the bridge can choose whether to retry, log, or
// fall back to non-MSC4350 behaviour.
func TestBuildImpersonatableDeviceKeys_SignerError(t *testing.T) {
	signer := &recordingSigner{signErr: errSign}
	_, err := BuildImpersonatableDeviceKeys(
		signer,
		testGhostUserID, testGhostDeviceID,
		testBotUserID, testBotDeviceID,
		testBotSigningKey, testBotIdentityKey,
	)
	if err == nil {
		t.Fatal("expected signer error to propagate, got nil")
	}
	if !strings.Contains(err.Error(), "sign impersonatable device") {
		t.Errorf("error should wrap with context; got %v", err)
	}
}

// TestBuildImpersonatableDeviceKeys_RequiredArgs guards each pre-flight
// check independently so a future refactor can't silently drop one.
func TestBuildImpersonatableDeviceKeys_RequiredArgs(t *testing.T) {
	signer := &recordingSigner{sigToReturn: testSignature}

	cases := []struct {
		name string
		mut  func(args *argSet)
	}{
		{"nil signer", func(a *argSet) { a.signer = nil }},
		{"empty ghost user", func(a *argSet) { a.ghostUser = "" }},
		{"empty ghost device", func(a *argSet) { a.ghostDevice = "" }},
		{"empty bot user", func(a *argSet) { a.botUser = "" }},
		{"empty bot device", func(a *argSet) { a.botDevice = "" }},
		{"empty bot signing key", func(a *argSet) { a.botSigning = "" }},
		{"empty bot identity key", func(a *argSet) { a.botIdentity = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := defaultArgs(signer)
			tc.mut(&args)
			_, err := BuildImpersonatableDeviceKeys(
				args.signer,
				args.ghostUser, args.ghostDevice,
				args.botUser, args.botDevice,
				args.botSigning, args.botIdentity,
			)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
		})
	}
}

// TestBuildImpersonatableDeviceKeys_JSONShape ensures the serialized
// output uses the unstable JSON key (we MUST NOT ship "impersonator"
// until MSC4350 stabilizes) and otherwise has the shape Synapse's
// MSC4350 upload validator expects.
func TestBuildImpersonatableDeviceKeys_JSONShape(t *testing.T) {
	signer := &recordingSigner{sigToReturn: testSignature}
	dk, err := BuildImpersonatableDeviceKeys(
		signer,
		testGhostUserID, testGhostDeviceID,
		testBotUserID, testBotDeviceID,
		testBotSigningKey, testBotIdentityKey,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, err := json.Marshal(dk)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("re-unmarshal failed: %v", err)
	}

	imp, ok := asMap["fi.mau.msc4350.impersonator"].(map[string]any)
	if !ok {
		t.Fatalf("missing unstable impersonator key; got keys: %v", keysOf(asMap))
	}
	if _, hasSigs := imp["signatures"]; hasSigs {
		t.Errorf("embedded impersonator MUST NOT have a signatures field; got %#v", imp)
	}
	if _, hasStable := asMap["impersonator"]; hasStable {
		t.Errorf("stable 'impersonator' key MUST NOT be emitted while MSC4350 is unstable")
	}
	if algs, _ := asMap["algorithms"].([]any); len(algs) != 0 {
		t.Errorf("top-level algorithms must serialize as [], got %v", algs)
	}
	if keys, _ := asMap["keys"].(map[string]any); len(keys) != 0 {
		t.Errorf("top-level keys must serialize as {}, got %v", keys)
	}
}

// --- helpers ---

type argSet struct {
	signer      ImpersonatorSigner
	ghostUser   id.UserID
	ghostDevice id.DeviceID
	botUser     id.UserID
	botDevice   id.DeviceID
	botSigning  id.SigningKey
	botIdentity id.IdentityKey
}

func defaultArgs(s ImpersonatorSigner) argSet {
	return argSet{
		signer:      s,
		ghostUser:   testGhostUserID,
		ghostDevice: testGhostDeviceID,
		botUser:     testBotUserID,
		botDevice:   testBotDeviceID,
		botSigning:  testBotSigningKey,
		botIdentity: testBotIdentityKey,
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

type sentinelErr string

func (e sentinelErr) Error() string { return string(e) }

const errSign sentinelErr = "deliberate signer failure for test"
