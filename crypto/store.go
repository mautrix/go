// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"maunium.net/go/olm"
)

type Store interface {
	Key() []byte

	SaveAccount(*olm.Account)
	LoadAccount() *olm.Account

	LoadSessions() []*olm.Session
	SaveSession(string, *olm.Session)
}
