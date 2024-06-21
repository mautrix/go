// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pk

import "maunium.net/go/mautrix/crypto/olm"

func init() {
	olm.InitNewPKSigningFromSeed = func(seed []byte) (olm.PKSigning, error) {
		return NewSigningFromSeed(seed)
	}
	olm.InitNewPKSigning = func() (olm.PKSigning, error) {
		return NewSigning()
	}
	olm.InitNewPKDecryptionFromPrivateKey = func(privateKey []byte) (olm.PKDecryption, error) {
		return NewDecryptionFromPrivate(privateKey)
	}
}
