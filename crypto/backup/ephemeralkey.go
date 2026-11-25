// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backup

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// EphemeralKey is a wrapper around an ECDH X25519 public key that implements
// JSON marshalling and unmarshalling.
type EphemeralKey struct {
	*ecdh.PublicKey
}

func (k *EphemeralKey) MarshalJSONTo(enc *jsontext.Encoder) error {
	if k == nil || k.PublicKey == nil {
		return enc.WriteToken(jsontext.Null)
	}
	return enc.WriteToken(jsontext.String(base64.RawStdEncoding.EncodeToString(k.Bytes())))
}

func (k *EphemeralKey) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var keyStr string
	err := json.UnmarshalDecode(dec, &keyStr)
	if err != nil {
		return err
	}

	keyBytes, err := base64.RawStdEncoding.DecodeString(keyStr)
	if err != nil {
		return err
	}
	k.PublicKey, err = ecdh.X25519().NewPublicKey(keyBytes)
	return err
}
