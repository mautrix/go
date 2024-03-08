// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package olm

import (
	"maunium.net/go/mautrix/crypto/goolm/pk"
	"maunium.net/go/mautrix/id"
)

// PKSigning is an interface for signing messages.
type PKSigning interface {
	// Seed returns the seed of the key.
	Seed() []byte

	// PublicKey returns the public key.
	PublicKey() id.Ed25519

	// Sign creates a signature for the given message using this key.
	Sign(message []byte) ([]byte, error)

	// SignJSON creates a signature for the given object after encoding it to
	// canonical JSON.
	SignJSON(obj any) (string, error)
}

var _ PKSigning = (*pk.Signing)(nil)

// PKDecryption is an interface for decrypting messages.
type PKDecryption interface {
	// PublicKey returns the public key.
	PublicKey() id.Curve25519

	// Decrypt verifies and decrypts the given message.
	Decrypt(ciphertext, mac []byte, key id.Curve25519) ([]byte, error)
}

var _ PKDecryption = (*pk.Decryption)(nil)
