// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package session

import (
	"maunium.net/go/mautrix/crypto/olm"
)

func init() {
	// Inbound Session
	olm.InitInboundGroupSessionFromPickled = func(pickled, key []byte) (olm.InboundGroupSession, error) {
		if len(pickled) == 0 {
			return nil, olm.EmptyInput
		}
		if len(key) == 0 {
			key = []byte(" ")
		}
		return MegolmInboundSessionFromPickled(pickled, key)
	}
	olm.InitNewInboundGroupSession = func(sessionKey []byte) (olm.InboundGroupSession, error) {
		if len(sessionKey) == 0 {
			return nil, olm.EmptyInput
		}
		return NewMegolmInboundSession(sessionKey)
	}
	olm.InitInboundGroupSessionImport = func(sessionKey []byte) (olm.InboundGroupSession, error) {
		if len(sessionKey) == 0 {
			return nil, olm.EmptyInput
		}
		return NewMegolmInboundSessionFromExport(sessionKey)
	}
	olm.InitBlankInboundGroupSession = func() olm.InboundGroupSession {
		return &MegolmInboundSession{}
	}

	// Outbound Session
	olm.InitNewOutboundGroupSessionFromPickled = func(pickled, key []byte) (olm.OutboundGroupSession, error) {
		if len(pickled) == 0 {
			return nil, olm.EmptyInput
		}
		lenKey := len(key)
		if lenKey == 0 {
			key = []byte(" ")
		}
		return MegolmOutboundSessionFromPickled(pickled, key)
	}
	olm.InitNewOutboundGroupSession = func() (olm.OutboundGroupSession, error) { return NewMegolmOutboundSession() }
	olm.InitNewBlankOutboundGroupSession = func() olm.OutboundGroupSession { return &MegolmOutboundSession{} }

	// Olm Session
	olm.InitSessionFromPickled = func(pickled, key []byte) (olm.Session, error) {
		return OlmSessionFromPickled(pickled, key)
	}
	olm.InitNewBlankSession = func() olm.Session {
		return NewOlmSession()
	}
}
