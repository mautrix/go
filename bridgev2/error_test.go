// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
)

func TestRespError_As(t *testing.T) {
	mautrixErr := mautrix.MNotFound.WithMessage("meow")
	bridgeErr := bridgev2.RespError(mautrixErr)

	assert.ErrorIs(t, bridgeErr, mautrixErr)
	reMautrixErr, ok := errors.AsType[mautrix.RespError](bridgeErr)
	require.True(t, ok)
	assert.Equal(t, reMautrixErr, mautrixErr)
}
