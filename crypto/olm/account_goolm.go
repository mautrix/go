// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goolm

package olm

import "maunium.net/go/mautrix/crypto/goolm/account"

// NewAccount creates a new Account.
func NewAccount() Account {
	return account.NewAccount()
}

func NewBlankAccount() Account {
	return &account.Account{}
}
