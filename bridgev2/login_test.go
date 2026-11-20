// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/bridgev2"
)

func TestClientCapabilities_Has(t *testing.T) {
	caps := bridgev2.ClientCapabilities{bridgev2.ClientCapabilityHTTP}
	assert.True(t, caps.Has(bridgev2.ClientCapabilityHTTP))
	assert.False(t, caps.Has(bridgev2.ClientCapabilityWebAuthn))
	assert.False(t, caps.Has(bridgev2.ClientCapabilityWebSocket))

	for _, empty := range []bridgev2.ClientCapabilities{nil, {}} {
		assert.False(t, empty.Has(bridgev2.ClientCapabilityWebAuthn))
		assert.False(t, empty.Has(bridgev2.ClientCapabilityHTTP))
	}
}

func TestClientCapabilities_HasAll(t *testing.T) {
	caps := bridgev2.ClientCapabilities{bridgev2.ClientCapabilityWebAuthn}
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

func TestClientCapabilities_CheckLoginStep(t *testing.T) {
	webAuthnStep := &bridgev2.LoginStep{Type: bridgev2.LoginStepTypeWebAuthn}
	userInputStep := &bridgev2.LoginStep{Type: bridgev2.LoginStepTypeUserInput}

	for _, caps := range []bridgev2.ClientCapabilities{nil, {bridgev2.ClientCapabilityHTTP}} {
		var respErr bridgev2.RespError
		require.ErrorAs(t, caps.CheckLoginStep(webAuthnStep), &respErr)
		assert.Equal(t, bridgev2.ErrMissingClientCapability.ErrCode, respErr.ErrCode)
		assert.NoError(t, caps.CheckLoginStep(userInputStep))
	}
	assert.NoError(t, bridgev2.ClientCapabilities{bridgev2.ClientCapabilityWebAuthn}.CheckLoginStep(webAuthnStep))
}
