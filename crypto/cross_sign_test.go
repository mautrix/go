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
	"go.mau.fi/util/dbutil"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/crypto/olm"
	"github.com/element-hq/mautrix-go/id"
)

var noopLogger = zerolog.Nop()

func getOlmMachine(t *testing.T) *OlmMachine {
	rawDB, err := sql.Open("sqlite3", ":memory:?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("Error opening db: %v", err)
	}
	db, err := dbutil.NewWithDB(rawDB, "sqlite3")
	if err != nil {
		t.Fatalf("Error opening db: %v", err)
	}
	sqlStore := NewSQLCryptoStore(db, nil, "accid", id.DeviceID("dev"), []byte("test"))
	if err = sqlStore.DB.Upgrade(context.TODO()); err != nil {
		t.Fatalf("Error creating tables: %v", err)
	}

	userID := id.UserID("@mautrix")
	mk, _ := olm.NewPkSigning()
	ssk, _ := olm.NewPkSigning()
	usk, _ := olm.NewPkSigning()

	sqlStore.PutCrossSigningKey(context.TODO(), userID, id.XSUsageMaster, mk.PublicKey)
	sqlStore.PutCrossSigningKey(context.TODO(), userID, id.XSUsageSelfSigning, ssk.PublicKey)
	sqlStore.PutCrossSigningKey(context.TODO(), userID, id.XSUsageUserSigning, usk.PublicKey)

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
	if m.IsDeviceTrusted(ownDevice) {
		t.Error("Own device trusted while it shouldn't be")
	}

	m.CryptoStore.PutSignature(context.TODO(), ownDevice.UserID, m.CrossSigningKeys.SelfSigningKey.PublicKey,
		ownDevice.UserID, m.CrossSigningKeys.MasterKey.PublicKey, "sig1")
	m.CryptoStore.PutSignature(context.TODO(), ownDevice.UserID, ownDevice.SigningKey,
		ownDevice.UserID, m.CrossSigningKeys.SelfSigningKey.PublicKey, "sig2")

	if trusted, _ := m.IsUserTrusted(context.TODO(), ownDevice.UserID); !trusted {
		t.Error("Own user not trusted while they should be")
	}
	if !m.IsDeviceTrusted(ownDevice) {
		t.Error("Own device not trusted while it should be")
	}
}

func TestTrustOtherUser(t *testing.T) {
	m := getOlmMachine(t)
	otherUser := id.UserID("@user")
	if trusted, _ := m.IsUserTrusted(context.TODO(), otherUser); trusted {
		t.Error("Other user trusted while they shouldn't be")
	}

	theirMasterKey, _ := olm.NewPkSigning()
	m.CryptoStore.PutCrossSigningKey(context.TODO(), otherUser, id.XSUsageMaster, theirMasterKey.PublicKey)

	m.CryptoStore.PutSignature(context.TODO(), m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey,
		m.Client.UserID, m.CrossSigningKeys.MasterKey.PublicKey, "sig1")

	// sign them with self-signing instead of user-signing key
	m.CryptoStore.PutSignature(context.TODO(), otherUser, theirMasterKey.PublicKey,
		m.Client.UserID, m.CrossSigningKeys.SelfSigningKey.PublicKey, "invalid_sig")

	if trusted, _ := m.IsUserTrusted(context.TODO(), otherUser); trusted {
		t.Error("Other user trusted before their master key has been signed with our user-signing key")
	}

	m.CryptoStore.PutSignature(context.TODO(), otherUser, theirMasterKey.PublicKey,
		m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey, "sig2")

	if trusted, _ := m.IsUserTrusted(context.TODO(), otherUser); !trusted {
		t.Error("Other user not trusted while they should be")
	}
}

func TestTrustOtherDevice(t *testing.T) {
	m := getOlmMachine(t)
	otherUser := id.UserID("@user")
	theirDevice := &id.Device{
		UserID:     otherUser,
		DeviceID:   "theirDevice",
		SigningKey: id.Ed25519("theirDeviceKey"),
	}
	if trusted, _ := m.IsUserTrusted(context.TODO(), otherUser); trusted {
		t.Error("Other user trusted while they shouldn't be")
	}
	if m.IsDeviceTrusted(theirDevice) {
		t.Error("Other device trusted while it shouldn't be")
	}

	theirMasterKey, _ := olm.NewPkSigning()
	m.CryptoStore.PutCrossSigningKey(context.TODO(), otherUser, id.XSUsageMaster, theirMasterKey.PublicKey)
	theirSSK, _ := olm.NewPkSigning()
	m.CryptoStore.PutCrossSigningKey(context.TODO(), otherUser, id.XSUsageSelfSigning, theirSSK.PublicKey)

	m.CryptoStore.PutSignature(context.TODO(), m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey,
		m.Client.UserID, m.CrossSigningKeys.MasterKey.PublicKey, "sig1")
	m.CryptoStore.PutSignature(context.TODO(), otherUser, theirMasterKey.PublicKey,
		m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey, "sig2")

	if trusted, _ := m.IsUserTrusted(context.TODO(), otherUser); !trusted {
		t.Error("Other user not trusted while they should be")
	}

	m.CryptoStore.PutSignature(context.TODO(), otherUser, theirSSK.PublicKey,
		otherUser, theirMasterKey.PublicKey, "sig3")

	if m.IsDeviceTrusted(theirDevice) {
		t.Error("Other device trusted before it has been signed with user's SSK")
	}

	m.CryptoStore.PutSignature(context.TODO(), otherUser, theirDevice.SigningKey,
		otherUser, theirSSK.PublicKey, "sig4")

	if !m.IsDeviceTrusted(theirDevice) {
		t.Error("Other device not trusted while it should be")
	}
}
