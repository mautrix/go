// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package goolm

import (
	"maunium.net/go/mautrix/crypto/goolm/account"
	"maunium.net/go/mautrix/crypto/goolm/pk"
	"maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/olm"
)

func Register() {
	olm.Driver = "goolm"

	olm.GetVersion = func() (major, minor, patch uint8) {
		return 3, 2, 15
	}
	olm.SetPickleKeyImpl = func(key []byte) {
		panic("gob and json encoding is deprecated and not supported with goolm")
	}

	account.Register()
	pk.Register()
	session.Register()
}
