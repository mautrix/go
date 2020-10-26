// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"database/sql"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/olm"
	sqlUpgrade "maunium.net/go/mautrix/crypto/sql_store_upgrade"
	"maunium.net/go/mautrix/id"
)

func getOlmMachine(t *testing.T) *OlmMachine {
	db, err := sql.Open("sqlite3", ":memory:?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("Error opening db: %v", err)
	}
	sqlUpgrade.Upgrade(db, "sqlite3")
	sqlStore := NewSQLCryptoStore(db, "sqlite3", "accid", id.DeviceID("dev"), []byte("test"), emptyLogger{})

	userID := id.UserID("@mautrix")
	mk, _ := olm.NewPkSigning()
	ssk, _ := olm.NewPkSigning()
	usk, _ := olm.NewPkSigning()

	sqlStore.PutCrossSigningKey(userID, id.XSUsageMaster, mk.PublicKey)
	sqlStore.PutCrossSigningKey(userID, id.XSUsageSelfSigning, ssk.PublicKey)
	sqlStore.PutCrossSigningKey(userID, id.XSUsageUserSigning, usk.PublicKey)

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
		Log: emptyLogger{},
	}
}

func TestTrustOwnDevice(t *testing.T) {
	m := getOlmMachine(t)
	ownDevice := &DeviceIdentity{
		UserID:     m.Client.UserID,
		DeviceID:   "device",
		SigningKey: id.Ed25519("deviceKey"),
	}
	if m.IsDeviceTrusted(ownDevice) {
		t.Error("Own device trusted while it shouldn't be")
	}

	m.CryptoStore.PutSignature(ownDevice.UserID, m.CrossSigningKeys.SelfSigningKey.PublicKey,
		ownDevice.UserID, m.CrossSigningKeys.MasterKey.PublicKey, "sig1")
	m.CryptoStore.PutSignature(ownDevice.UserID, ownDevice.SigningKey,
		ownDevice.UserID, m.CrossSigningKeys.SelfSigningKey.PublicKey, "sig2")

	if !m.IsUserTrusted(ownDevice.UserID) {
		t.Error("Own user not trusted while they should be")
	}
	if !m.IsDeviceTrusted(ownDevice) {
		t.Error("Own device not trusted while it should be")
	}
}

func TestTrustOtherUser(t *testing.T) {
	m := getOlmMachine(t)
	otherUser := id.UserID("@user")
	if m.IsUserTrusted(otherUser) {
		t.Error("Other user trusted while they shouldn't be")
	}

	theirMasterKey, _ := olm.NewPkSigning()
	m.CryptoStore.PutCrossSigningKey(otherUser, id.XSUsageMaster, theirMasterKey.PublicKey)

	m.CryptoStore.PutSignature(m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey,
		m.Client.UserID, m.CrossSigningKeys.MasterKey.PublicKey, "sig1")

	// sign them with self-signing instead of user-signing key
	m.CryptoStore.PutSignature(otherUser, theirMasterKey.PublicKey,
		m.Client.UserID, m.CrossSigningKeys.SelfSigningKey.PublicKey, "invalid_sig")

	if m.IsUserTrusted(otherUser) {
		t.Error("Other user trusted before their master key has been signed with our user-signing key")
	}

	m.CryptoStore.PutSignature(otherUser, theirMasterKey.PublicKey,
		m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey, "sig2")

	if !m.IsUserTrusted(otherUser) {
		t.Error("Other user not trusted while they should be")
	}
}

func TestTrustOtherDevice(t *testing.T) {
	m := getOlmMachine(t)
	otherUser := id.UserID("@user")
	theirDevice := &DeviceIdentity{
		UserID:     otherUser,
		DeviceID:   "theirDevice",
		SigningKey: id.Ed25519("theirDeviceKey"),
	}
	if m.IsUserTrusted(otherUser) {
		t.Error("Other user trusted while they shouldn't be")
	}
	if m.IsDeviceTrusted(theirDevice) {
		t.Error("Other device trusted while it shouldn't be")
	}

	theirMasterKey, _ := olm.NewPkSigning()
	m.CryptoStore.PutCrossSigningKey(otherUser, id.XSUsageMaster, theirMasterKey.PublicKey)
	theirSSK, _ := olm.NewPkSigning()
	m.CryptoStore.PutCrossSigningKey(otherUser, id.XSUsageSelfSigning, theirSSK.PublicKey)

	m.CryptoStore.PutSignature(m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey,
		m.Client.UserID, m.CrossSigningKeys.MasterKey.PublicKey, "sig1")
	m.CryptoStore.PutSignature(otherUser, theirMasterKey.PublicKey,
		m.Client.UserID, m.CrossSigningKeys.UserSigningKey.PublicKey, "sig2")

	if !m.IsUserTrusted(otherUser) {
		t.Error("Other user not trusted while they should be")
	}

	m.CryptoStore.PutSignature(otherUser, theirSSK.PublicKey,
		otherUser, theirMasterKey.PublicKey, "sig3")

	if m.IsDeviceTrusted(theirDevice) {
		t.Error("Other device trusted before it has been signed with user's SSK")
	}

	m.CryptoStore.PutSignature(otherUser, theirDevice.SigningKey,
		otherUser, theirSSK.PublicKey, "sig4")

	if !m.IsDeviceTrusted(theirDevice) {
		t.Error("Other device not trusted while it should be")
	}
}
