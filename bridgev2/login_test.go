// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/bridgev2"
)

func TestClientCapabilities_Has(t *testing.T) {
	negotiated := bridgev2.ClientCapabilities{bridgev2.ClientCapabilityNegotiation, bridgev2.ClientCapabilityHTTP}
	assert.True(t, negotiated.Has(bridgev2.ClientCapabilityHTTP))
	assert.False(t, negotiated.Has(bridgev2.ClientCapabilityWebAuthn))
	assert.False(t, negotiated.Has(bridgev2.ClientCapabilityWebSocket))

	for _, legacy := range []bridgev2.ClientCapabilities{nil, {}, {bridgev2.ClientCapabilityHTTP}} {
		assert.False(t, legacy.Negotiated())
		assert.True(t, legacy.Has(bridgev2.ClientCapabilityWebAuthn))
		assert.False(t, legacy.Has(bridgev2.ClientCapabilityWebSocket))
	}
	assert.True(t, bridgev2.ClientCapabilities{bridgev2.ClientCapabilityHTTP}.Has(bridgev2.ClientCapabilityHTTP))
	assert.False(t, bridgev2.ClientCapabilities(nil).Has(bridgev2.ClientCapabilityHTTP))
}

func TestClientCapabilities_HasAll(t *testing.T) {
	caps := bridgev2.ClientCapabilities{bridgev2.ClientCapabilityNegotiation, bridgev2.ClientCapabilityWebAuthn}
	assert.True(t, caps.HasAll())
	assert.True(t, caps.HasAll(bridgev2.ClientCapabilityWebAuthn))
	assert.False(t, caps.HasAll(bridgev2.ClientCapabilityWebAuthn, bridgev2.ClientCapabilityHTTP))
}

func TestMissingClientCapabilityError(t *testing.T) {
	err := bridgev2.MissingClientCapabilityError(bridgev2.ClientCapabilityWebAuthn)
	assert.Equal(t, bridgev2.ErrMissingClientCapability.ErrCode, err.ErrCode)
	assert.Equal(t, bridgev2.ErrMissingClientCapability.StatusCode, err.StatusCode)
	assert.Contains(t, err.Error(), "webauthn")
}
