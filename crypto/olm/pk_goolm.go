// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// When the goolm build flag is enabled, this file will make [PKSigning]
// constructors use the goolm constuctors.

//go:build goolm

package olm

import "maunium.net/go/mautrix/crypto/goolm/pk"

// NewPKSigningFromSeed creates a new PKSigning object using the given seed.
func NewPKSigningFromSeed(seed []byte) (PKSigning, error) {
	return pk.NewSigningFromSeed(seed)
}

// NewPKSigning creates a new [PKSigning] object, containing a key pair for
// signing messages.
func NewPKSigning() (PKSigning, error) {
	return pk.NewSigning()
}

func NewPKDecryption(privateKey []byte) (PKDecryption, error) {
	return pk.NewDecryption()
}
