// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package olm_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/exerrors"
	"golang.org/x/exp/maps"

	"maunium.net/go/mautrix/crypto/goolm/account"
	"maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/libolm"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
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

	goolmSession, err := session.OlmSessionFromPickled(bytes.Clone(pickledDataFromLibOlm), pickleKey)
	assert.NoError(t, err)

	libolmSession, err := libolm.SessionFromPickled(bytes.Clone(pickledDataFromLibOlm), pickleKey)
	assert.NoError(t, err)

	goolmPickled, err := goolmSession.Pickle(pickleKey)
	require.NoError(t, err)
	assert.Equal(t, pickledDataFromLibOlm, goolmPickled)

	libolmPickled, err := libolmSession.Pickle(pickleKey)
	require.NoError(t, err)
	assert.Equal(t, pickledDataFromLibOlm, libolmPickled)
}

func TestSession_EncryptDecrypt(t *testing.T) {
	combos := [][2]olm.Account{
		{exerrors.Must(libolm.NewAccount()), exerrors.Must(libolm.NewAccount())},
		{exerrors.Must(account.NewAccount()), exerrors.Must(account.NewAccount())},
		{exerrors.Must(libolm.NewAccount()), exerrors.Must(account.NewAccount())},
		{exerrors.Must(account.NewAccount()), exerrors.Must(libolm.NewAccount())},
	}

	for _, combo := range combos {
		receiver, sender := combo[0], combo[1]
		require.NoError(t, receiver.GenOneTimeKeys(50))
		require.NoError(t, sender.GenOneTimeKeys(50))

		_, receiverCurve25519, err := receiver.IdentityKeys()
		require.NoError(t, err)
		accountAOTKs, err := receiver.OneTimeKeys()
		require.NoError(t, err)

		senderSession, err := sender.NewOutboundSession(receiverCurve25519, accountAOTKs[maps.Keys(accountAOTKs)[0]])
		require.NoError(t, err)

		// Send a couple pre-key messages from sender -> receiver.
		var receiverSession olm.Session
		for i := 0; i < 10; i++ {
			msgType, ciphertext, err := senderSession.Encrypt([]byte(fmt.Sprintf("prekey %d", i)))
			require.NoError(t, err)
			assert.Equal(t, id.OlmMsgTypePreKey, msgType)

			receiverSession, err = receiver.NewInboundSession(string(ciphertext))
			require.NoError(t, err)

			decrypted, err := receiverSession.Decrypt(string(ciphertext), msgType)
			require.NoError(t, err)
			assert.Equal(t, []byte(fmt.Sprintf("prekey %d", i)), decrypted)
		}

		// Send some messages from receiver -> sender.
		for i := 0; i < 10; i++ {
			msgType, ciphertext, err := receiverSession.Encrypt([]byte(fmt.Sprintf("response %d", i)))
			require.NoError(t, err)
			assert.Equal(t, id.OlmMsgTypeMsg, msgType)

			decrypted, err := senderSession.Decrypt(string(ciphertext), msgType)
			require.NoError(t, err)
			assert.Equal(t, []byte(fmt.Sprintf("response %d", i)), decrypted)
		}

		// Send some more messages from sender -> receiver
		for i := 0; i < 10; i++ {
			msgType, ciphertext, err := senderSession.Encrypt([]byte(fmt.Sprintf("%d", i)))
			require.NoError(t, err)
			assert.Equal(t, id.OlmMsgTypeMsg, msgType)

			decrypted, err := receiverSession.Decrypt(string(ciphertext), msgType)
			require.NoError(t, err)
			assert.Equal(t, []byte(fmt.Sprintf("%d", i)), decrypted)
		}
	}
}
