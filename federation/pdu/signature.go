// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"maunium.net/go/mautrix/federation/signutil"
	"maunium.net/go/mautrix/id"
)

func (pdu *PDU) Sign(roomVersion id.RoomVersion, serverName string, keyID id.KeyID, privateKey ed25519.PrivateKey) error {
	err := pdu.FillContentHash()
	if err != nil {
		return err
	}
	rawJSON, err := marshalCanonical(pdu.Clone().RedactForSignature(roomVersion))
	if err != nil {
		return fmt.Errorf("failed to marshal redacted PDU to sign: %w", err)
	}
	signature := ed25519.Sign(privateKey, rawJSON)
	if pdu.Signatures == nil {
		pdu.Signatures = make(map[string]map[id.KeyID]string)
	}
	if _, ok := pdu.Signatures[serverName]; !ok {
		pdu.Signatures[serverName] = make(map[id.KeyID]string)
	}
	pdu.Signatures[serverName][keyID] = base64.RawStdEncoding.EncodeToString(signature)
	return nil
}

func (pdu *PDU) VerifySignature(roomVersion id.RoomVersion, serverName string, getKey GetKeyFunc) error {
	rawJSON, err := marshalCanonical(pdu.Clone().RedactForSignature(roomVersion))
	if err != nil {
		return fmt.Errorf("failed to marshal redacted PDU to verify signature: %w", err)
	}
	verified := false
	for keyID, sig := range pdu.Signatures[serverName] {
		originServerTS := time.UnixMilli(pdu.OriginServerTS)
		key, validUntil, err := getKey(serverName, keyID, originServerTS)
		if err != nil {
			return fmt.Errorf("failed to get key %s for %s: %w", keyID, serverName, err)
		} else if key == "" {
			return fmt.Errorf("key %s not found for %s", keyID, serverName)
		} else if validUntil.Before(originServerTS) && roomVersion.EnforceSigningKeyValidity() {
			return fmt.Errorf("key %s for %s is only valid until %s, but event is from %s", keyID, serverName, validUntil, originServerTS)
		} else if err = signutil.VerifyJSONRaw(key, sig, rawJSON); err != nil {
			return fmt.Errorf("failed to verify signature from key %s: %w", keyID, err)
		} else {
			verified = true
		}
	}
	if !verified {
		return fmt.Errorf("no verifiable signatures found for server %s", serverName)
	}
	return nil
}
