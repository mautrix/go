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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.mau.fi/util/exgjson"
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

	Raw json.RawMessage `json:"-"`
}

type QueryKeysResponse struct {
	ServerKeys []*ServerKeyResponse `json:"server_keys"`
}

func (skr *ServerKeyResponse) HasKey(keyID id.KeyID) bool {
	if skr == nil {
		return false
	} else if _, ok := skr.VerifyKeys[keyID]; ok {
		return true
	}
	return false
}

func (skr *ServerKeyResponse) VerifySelfSignature() error {
	for keyID, key := range skr.VerifyKeys {
		if err := VerifyJSON(skr.ServerName, keyID, key.Key, skr.Raw); err != nil {
			return fmt.Errorf("failed to verify self signature for key %s: %w", keyID, err)
		}
	}
	return nil
}

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

var ErrSignatureNotFound = errors.New("signature not found")
var ErrInvalidSignature = errors.New("invalid signature")

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

type marshalableSKR ServerKeyResponse

func (skr *ServerKeyResponse) UnmarshalJSON(data []byte) error {
	skr.Raw = data
	return json.Unmarshal(data, (*marshalableSKR)(skr))
}

type ServerVerifyKey struct {
	Key id.SigningKey `json:"key"`
}

func (svk *ServerVerifyKey) Decode() (ed25519.PublicKey, error) {
	return base64.RawStdEncoding.DecodeString(string(svk.Key))
}

type OldVerifyKey struct {
	Key       id.SigningKey      `json:"key"`
	ExpiredTS jsontime.UnixMilli `json:"expired_ts"`
}

func (sk *SigningKey) SignJSON(data any) (string, error) {
	marshaled, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	marshaled, err = sjson.DeleteBytes(marshaled, "signatures")
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sk.SignRawJSON(marshaled)), nil
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
			sk.ID: signature,
		},
	}
	return skr
}
