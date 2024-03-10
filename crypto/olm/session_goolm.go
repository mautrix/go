// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// When the goolm build flag is enabled, this file will make [PKSigning]
// constructors use the goolm constuctors.

//go:build goolm

package olm

import "maunium.net/go/mautrix/crypto/goolm/session"

// SessionFromPickled loads a Session from a pickled base64 string.  Decrypts
// the Session using the supplied key.  Returns error on failure.
func SessionFromPickled(pickled, key []byte) (Session, error) {
	if len(pickled) == 0 {
		return nil, EmptyInput
	}
	s := session.NewOlmSession()
	return s, s.Unpickle(pickled, key)
}

func NewBlankSession() Session {
	return session.NewOlmSession()
}
