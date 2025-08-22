// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package signutil

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.mau.fi/util/exgjson"

	"github.com/iKonoTelecomunicaciones/go/crypto/canonicaljson"
	"github.com/iKonoTelecomunicaciones/go/id"
)

var ErrSignatureNotFound = errors.New("signature not found")
var ErrInvalidSignature = errors.New("invalid signature")

func VerifyJSON(serverName string, keyID id.KeyID, key id.SigningKey, data any) error {
	var err error
	message, ok := data.(json.RawMessage)
	if !ok {
		message, err = json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal data: %w", err)
		}
	}
	sigVal := gjson.GetBytes(message, exgjson.Path("signatures", serverName, string(keyID)))
	if sigVal.Type != gjson.String {
		return ErrSignatureNotFound
	}
	message, err = sjson.DeleteBytes(message, "signatures")
	if err != nil {
		return fmt.Errorf("failed to delete signatures: %w", err)
	}
	message, err = sjson.DeleteBytes(message, "unsigned")
	if err != nil {
		return fmt.Errorf("failed to delete unsigned: %w", err)
	}
	return VerifyJSONRaw(key, sigVal.Str, message)
}

func VerifyJSONRaw(key id.SigningKey, sig string, message json.RawMessage) error {
	sigBytes, err := base64.RawStdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	keyBytes, err := base64.RawStdEncoding.DecodeString(string(key))
	if err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}
	message = canonicaljson.CanonicalJSONAssumeValid(message)
	if !ed25519.Verify(keyBytes, message, sigBytes) {
		return ErrInvalidSignature
	}
	return nil
}
