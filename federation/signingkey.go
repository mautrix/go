// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.mau.fi/util/jsontime"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/id"
)

// SigningKey is a Matrix federation signing key pair.
type SigningKey struct {
	ID   id.KeyID
	Pub  id.SigningKey
	Priv ed25519.PrivateKey
}

// SynapseString returns a string representation of the private key compatible with Synapse's .signing.key file format.
//
// The output of this function can be parsed back into a [SigningKey] using the [ParseSynapseKey] function.
func (sk *SigningKey) SynapseString() string {
	alg, id := sk.ID.Parse()
	return fmt.Sprintf("%s %s %s", alg, id, base64.RawStdEncoding.EncodeToString(sk.Priv.Seed()))
}

// ParseSynapseKey parses a Synapse-compatible private key string into a SigningKey.
func ParseSynapseKey(key string) (*SigningKey, error) {
	parts := strings.Split(key, " ")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid key format (expected 3 space-separated parts, got %d)", len(parts))
	} else if parts[0] != string(id.KeyAlgorithmEd25519) {
		return nil, fmt.Errorf("unsupported key algorithm %s (only ed25519 is supported)", parts[0])
	}
	seed, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := base64.RawStdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	return &SigningKey{
		ID:   id.NewKeyID(id.KeyAlgorithmEd25519, parts[1]),
		Pub:  id.SigningKey(pub),
		Priv: priv,
	}, nil
}

// GenerateSigningKey generates a new random signing key.
func GenerateSigningKey() *SigningKey {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return &SigningKey{
		ID:   id.NewKeyID(id.KeyAlgorithmEd25519, base64.RawURLEncoding.EncodeToString(pub[:4])),
		Pub:  id.SigningKey(base64.RawStdEncoding.EncodeToString(pub)),
		Priv: priv,
	}
}

// ServerKeyResponse is the response body for the `GET /_matrix/key/v2/server` endpoint.
// It's also used inside the query endpoint response structs.
type ServerKeyResponse struct {
	ServerName    string                         `json:"server_name"`
	VerifyKeys    map[id.KeyID]ServerVerifyKey   `json:"verify_keys"`
	OldVerifyKeys map[id.KeyID]OldVerifyKey      `json:"old_verify_keys,omitempty"`
	Signatures    map[string]map[id.KeyID]string `json:"signatures,omitempty"`
	ValidUntilTS  jsontime.UnixMilli             `json:"valid_until_ts"`
}

type ServerVerifyKey struct {
	Key id.SigningKey `json:"key"`
}

type OldVerifyKey struct {
	Key       id.SigningKey      `json:"key"`
	ExpiredTS jsontime.UnixMilli `json:"expired_ts"`
}

func (sk *SigningKey) SignJSON(data any) ([]byte, error) {
	marshaled, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return sk.SignRawJSON(marshaled), nil
}

func (sk *SigningKey) SignRawJSON(data json.RawMessage) []byte {
	return ed25519.Sign(sk.Priv, canonicaljson.CanonicalJSONAssumeValid(data))
}

// GenerateKeyResponse generates a key response signed by this key with the given server name and optionally some old verify keys.
func (sk *SigningKey) GenerateKeyResponse(serverName string, oldVerifyKeys map[id.KeyID]OldVerifyKey) *ServerKeyResponse {
	skr := &ServerKeyResponse{
		ServerName:    serverName,
		OldVerifyKeys: oldVerifyKeys,
		ValidUntilTS:  jsontime.UM(time.Now().Add(24 * time.Hour)),
		VerifyKeys: map[id.KeyID]ServerVerifyKey{
			sk.ID: {Key: sk.Pub},
		},
	}
	signature, err := sk.SignJSON(skr)
	if err != nil {
		panic(err)
	}
	skr.Signatures = map[string]map[id.KeyID]string{
		serverName: {
			sk.ID: base64.RawURLEncoding.EncodeToString(signature),
		},
	}
	return skr
}
