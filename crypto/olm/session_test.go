// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package olm_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/libolm"
)

func TestBlankSession(t *testing.T) {
	libolmSession := libolm.NewBlankSession()
	session := session.NewOlmSession()

	assert.Equal(t, libolmSession.ID(), session.ID())
	assert.Equal(t, libolmSession.HasReceivedMessage(), session.HasReceivedMessage())
	assert.Equal(t, libolmSession.EncryptMsgType(), session.EncryptMsgType())
	assert.Equal(t, libolmSession.Describe(), session.Describe())

	libolmPickled, err := libolmSession.Pickle([]byte("test"))
	assert.NoError(t, err)
	goolmPickled, err := session.Pickle([]byte("test"))
	assert.NoError(t, err)
	assert.Equal(t, goolmPickled, libolmPickled)
}

func TestSessionPickle(t *testing.T) {
	pickledDataFromLibOlm := []byte("icDKYm0b4aO23WgUuOxdpPoxC0UlEOYPVeuduNH3IkpFsmnWx5KuEOpxGiZw5IuB/sSn2RZUCTiJ90IvgC7AClkYGHep9O8lpiqQX73XVKD9okZDCAkBc83eEq0DKYC7HBkGRAU/4T6QPIBBY3UK4QZwULLE/fLsi3j4YZBehMtnlsqgHK0q1bvX4cRznZItVKR4ro0O9EAk6LLxJtSnRu5elSUk7YXT")
	pickleKey := []byte("secret_key")

	goolmSession := session.NewOlmSession()
	err := goolmSession.Unpickle(pickledDataFromLibOlm, pickleKey)
	assert.NoError(t, err)

	libolmSession := libolm.NewBlankSession()
	err = libolmSession.Unpickle(pickledDataFromLibOlm, pickleKey)
	assert.NoError(t, err)

	// Reset the pickle data since libolmSession.Unpickle modifies it.
	pickledDataFromLibOlm = []byte("icDKYm0b4aO23WgUuOxdpPoxC0UlEOYPVeuduNH3IkpFsmnWx5KuEOpxGiZw5IuB/sSn2RZUCTiJ90IvgC7AClkYGHep9O8lpiqQX73XVKD9okZDCAkBc83eEq0DKYC7HBkGRAU/4T6QPIBBY3UK4QZwULLE/fLsi3j4YZBehMtnlsqgHK0q1bvX4cRznZItVKR4ro0O9EAk6LLxJtSnRu5elSUk7YXT")

	goolmPickled, err := goolmSession.Pickle(pickleKey)
	assert.NoError(t, err)
	assert.Equal(t, pickledDataFromLibOlm, goolmPickled)

	libolmPickled, err := libolmSession.Pickle(pickleKey)
	assert.Equal(t, pickledDataFromLibOlm, libolmPickled)
	assert.NoError(t, err)
}
