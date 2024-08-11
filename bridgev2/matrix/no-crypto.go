// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !cgo || nocrypto

package matrix

import (
	"errors"
)

func NewCryptoHelper(c *Connector) Crypto {
	if c.Config.Encryption.Allow {
		c.Log.Warn().Msg("Bridge built without end-to-bridge encryption, but encryption is enabled in config")
	} else {
		c.Log.Debug().Msg("Bridge built without end-to-bridge encryption")
	}
	return nil
}

var NoSessionFound = errors.New("nil")
var UnknownMessageIndex = NoSessionFound
var DuplicateMessageIndex = NoSessionFound
