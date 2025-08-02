// Copyright (c) 2020 Nikos Filippakis
// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"database/sql"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

var noopLogger = zerolog.Nop()

func getOlmMachine(t *testing.T) *OlmMachine {
	rawDB, err := sql.Open("sqlite3", ":memory:?_busy_timeout=5000")
	require.NoError(t, err, "Error opening raw database")
	db, err := dbutil.NewWithDB(rawDB, "sqlite3")
	require.NoError(t, err, "Error creating database wrapper")
	sqlStore := NewSQLCryptoStore(db, nil, "accid", id.DeviceID("dev"), []byte("test"))
	err = sqlStore.DB.Upgrade(context.TODO())
	require.NoError(t, err, "Error upgrading database")

	userID := id.UserID("@mautrix")
	mk, _ := olm.NewPKSigning()
	ssk, _ := olm.NewPKSigning()
	usk, _ := olm.NewPKSigning()

	sqlStore.PutCrossSigningKey(context.TODO(), userID, id.XSUsageMaster, mk.PublicKey())
	sqlStore.PutCrossSigningKey(context.TODO(), userID, id.XSUsageSelfSigning, ssk.PublicKey())
	sqlStore.PutCrossSigningKey(context.TODO(), userID, id.XSUsageUserSigning, usk.PublicKey())

	return &OlmMachine{
		CryptoStore: sqlStore,
		CrossSigningKeys: &CrossSigningKeysCache{
			MasterKey:      mk,
			SelfSigningKey: ssk,
			UserSigningKey: usk,
		},
		Client: &mautrix.Client{
			UserID: userID,
		},
		Log: &noopLogger,
	}
}

func TestTrustOwnDevice(t *testing.T) {
	m := getOlmMachine(t)
	ownDevice := &id.Device{
		UserID:     m.Client.UserID,
		DeviceID:   "device",
		SigningKey: id.Ed25519("deviceKey"),
	}
	assert.False(t, m.IsDeviceTrusted(context.TODO(), ownDevice), "Own device trusted while it shouldn't be")

	m.CryptoStore.PutSignature(context.TODO(), ownDevice.UserID, m.CrossSigningKeys.SelfSigningKey.PublicKey(),
		ownDevice.UserID, m.CrossSigningKeys.MasterKey.PublicKey(), "sig1")
	m.CryptoStore.PutSignature(context.TODO(), ownDevice.UserID, ownDevice.SigningKey,
		ownDevice.UserID, m.CrossSigningKeys.SelfSigningKey.PublicKey(), "sig2")

	trusted, err := m.IsUserTrusted(context.TODO(), ownDevice.UserID)
	require.NoError(t, err, "Error checking if own user is trusted")
	assert.True(t, trusted, "Own user not trusted while they should be")
	assert.True(t, m.IsDeviceTrusted(context.TODO(), ownDevice), "Own device not trusted while it should be")
}

func TestTrustOtherUser(t *testing.T) {
	m := getOlmMachine(t)
	otherUser := id.UserID("@user")
	trusted, err := m.IsUserTrusted(context.TODO(), otherUser)
	require.NoError(t, err, "Error checking if other user is trusted")
	assert.False(t, trusted, "Other user trusted while they shouldn't be")

	theirMasterKey, _ := olm.NewPKSigning()
	m.CryptoStore.PutCrossSigningKey(context.TODO(), otherUser, id.XSUsageMaster, theirMasterKey.PublicKey())

	m.CryptoStore.PutSignature(context.TODO(), m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey(),
		m.Client.UserID, m.CrossSigningKeys.MasterKey.PublicKey(), "sig1")

	// sign them with self-signing instead of user-signing key
	m.CryptoStore.PutSignature(context.TODO(), otherUser, theirMasterKey.PublicKey(),
		m.Client.UserID, m.CrossSigningKeys.SelfSigningKey.PublicKey(), "invalid_sig")

	trusted, err = m.IsUserTrusted(context.TODO(), otherUser)
	require.NoError(t, err, "Error checking if other user is trusted")
	assert.False(t, trusted, "Other user trusted before their master key has been signed with our user-signing key")

	m.CryptoStore.PutSignature(context.TODO(), otherUser, theirMasterKey.PublicKey(),
		m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey(), "sig2")

	trusted, err = m.IsUserTrusted(context.TODO(), otherUser)
	require.NoError(t, err, "Error checking if other user is trusted")
	assert.True(t, trusted, "Other user not trusted while they should be")
}

func TestTrustOtherDevice(t *testing.T) {
	m := getOlmMachine(t)
	otherUser := id.UserID("@user")
	theirDevice := &id.Device{
		UserID:     otherUser,
		DeviceID:   "theirDevice",
		SigningKey: id.Ed25519("theirDeviceKey"),
	}

	trusted, err := m.IsUserTrusted(context.TODO(), otherUser)
	require.NoError(t, err, "Error checking if other user is trusted")
	assert.False(t, trusted, "Other user trusted while they shouldn't be")
	assert.False(t, m.IsDeviceTrusted(context.TODO(), theirDevice), "Other device trusted while it shouldn't be")

	theirMasterKey, _ := olm.NewPKSigning()
	m.CryptoStore.PutCrossSigningKey(context.TODO(), otherUser, id.XSUsageMaster, theirMasterKey.PublicKey())
	theirSSK, _ := olm.NewPKSigning()
	m.CryptoStore.PutCrossSigningKey(context.TODO(), otherUser, id.XSUsageSelfSigning, theirSSK.PublicKey())

	m.CryptoStore.PutSignature(context.TODO(), m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey(),
		m.Client.UserID, m.CrossSigningKeys.MasterKey.PublicKey(), "sig1")
	m.CryptoStore.PutSignature(context.TODO(), otherUser, theirMasterKey.PublicKey(),
		m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey(), "sig2")

	trusted, err = m.IsUserTrusted(context.TODO(), otherUser)
	require.NoError(t, err, "Error checking if other user is trusted")
	assert.True(t, trusted, "Other user not trusted while they should be")

	m.CryptoStore.PutSignature(context.TODO(), otherUser, theirSSK.PublicKey(),
		otherUser, theirMasterKey.PublicKey(), "sig3")

	assert.False(t, m.IsDeviceTrusted(context.TODO(), theirDevice), "Other device trusted before it has been signed with user's SSK")

	m.CryptoStore.PutSignature(context.TODO(), otherUser, theirDevice.SigningKey,
		otherUser, theirSSK.PublicKey(), "sig4")

	assert.True(t, m.IsDeviceTrusted(context.TODO(), theirDevice), "Other device not trusted after it has been signed with user's SSK")
}
