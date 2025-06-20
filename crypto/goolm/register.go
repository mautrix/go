// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package goolm

import (
	// Need to import these subpackages to ensure they are registered
	_ "github.com/iKonoTelecomunicaciones/go/crypto/goolm/account"
	_ "github.com/iKonoTelecomunicaciones/go/crypto/goolm/pk"
	_ "github.com/iKonoTelecomunicaciones/go/crypto/goolm/session"

	"github.com/iKonoTelecomunicaciones/go/crypto/olm"
)

func init() {
	olm.GetVersion = func() (major, minor, patch uint8) {
		return 3, 2, 15
	}
	olm.SetPickleKeyImpl = func(key []byte) {
		panic("gob and json encoding is deprecated and not supported with goolm")
	}
}
