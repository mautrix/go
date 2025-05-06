// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exfmt"

	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/olm"
)

func TestExportKeys(t *testing.T) {
	acc := crypto.NewOlmAccount()
	sess := exerrors.Must(crypto.NewInboundGroupSession(
		acc.IdentityKey(),
		acc.SigningKey(),
		"!room:example.com",
		exerrors.Must(olm.NewOutboundGroupSession()).Key(),
		7*exfmt.Day,
		100,
		false,
	))
	data, err := crypto.ExportKeys("meow", []*crypto.InboundGroupSession{sess})
	assert.NoError(t, err)
	assert.Len(t, data, 836)
}
