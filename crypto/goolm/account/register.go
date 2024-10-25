// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package account

import (
	"maunium.net/go/mautrix/crypto/olm"
)

func init() {
	olm.InitNewAccount = func() (olm.Account, error) {
		return NewAccount()
	}
	olm.InitBlankAccount = func() olm.Account {
		return &Account{}
	}
	olm.InitNewAccountFromPickled = func(pickled, key []byte) (olm.Account, error) {
		return AccountFromPickled(pickled, key)
	}
}
