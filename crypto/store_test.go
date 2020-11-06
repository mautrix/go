// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"database/sql"
	"os"
	"strconv"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

const olmSessID = "sJlikQQKXp7UQjmS9/lyZCNUVJ2AmKyHbufPBaC7tpk"
const olmPickled = "L6cdv3JYO9OzhXbcjNSwl7ldN5bDvwmGyin+hISePETE6bO71DIlhqTC9YIhg21RDqRPH2HNl1MCyCw0hEXICWQyeJ9S7JLie" +
	"5PYxhqSSaTYaybvlvw34jvuSgEx0iotM6WNuWu5ocrsOo5Ye/3Nz7lBvxaw2rpS0jZnn7eV1n9GbINZk4YEVWrHOn7OxYfaGECJHDeAk/ameStiy" +
	"o1Gru0a/cmR0O3oKMyYnlXir0jS7oETMCsWk59GeVlz++j4aK0FK4g8/3fCMmLDXSatFjE9hoWDmeRwal58Y+XwX76Te/PiWtrFrinvCDEQJcZTa" +
	"qcCwp6sZrgLbmfBUBb0zJCogCmYw8m2"
const groupSession = "9ZbsRqJuETbjnxPpKv29n3dubP/m5PSLbr9I9CIWS2O86F/Og1JZXhqT+4fA5tovoPfdpk5QLh7PfDyjmgOcO9sSA37maJyzCy6Ap+uBZLAXp6VLJ0mjSvxi+PAbzGKDMqpn+pa+oeEIH6SFPG/2GGDSRoXVi5fttAClCIoav5RflWiMypKqnQRfkZR2Gx8glOaBiTzAd7m0X6XGfYIPol41JUIHfBLuJBfXQ0Uu5GScV4eKUWdJP2J6zzC2Hx8cZAhiBBzAza0CbGcnUK+YJXMYaJg92HiIo++l317LlsYUJ/P+gKOLafYR9/l8bAzxH7j5s31PnRs7mD1Bl6G1LFM+dPsGXUOLx6PlvlTlYYM/opai0uKKzT0Wk6zPoq9fN/smlXEPBtKlw2fqcytL4gOF0MrBPEca"

func getCryptoStores(t *testing.T) (map[string]Store, func()) {
	db, err := sql.Open("sqlite3", ":memory:?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("Error opening db: %v", err)
	}
	sqlStore := NewSQLCryptoStore(db, "sqlite3", "accid", id.DeviceID("dev"), []byte("test"), emptyLogger{})
	if err = sqlStore.CreateTables(); err != nil {
		t.Fatalf("Error creating tables: %v", err)
	}

	os.Remove("gob_store_test.gob")
	gobStore, err := NewGobStore("gob_store_test.gob")
	if err != nil {
		t.Fatalf("Error creating Gob store: %v", err)
	}

	return map[string]Store{
			"sql": sqlStore,
			"gob": gobStore,
		}, func() {
			os.Remove("gob_store_test.gob")
		}
}

func TestPutNextBatch(t *testing.T) {
	stores, cleanup := getCryptoStores(t)
	defer cleanup()
	store := stores["sql"].(*SQLCryptoStore)
	store.PutNextBatch("batch1")
	if batch := store.GetNextBatch(); batch != "batch1" {
		t.Errorf("Expected batch1, got %v", batch)
	}
}

func TestPutAccount(t *testing.T) {
	stores, cleanup := getCryptoStores(t)
	defer cleanup()
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			acc := NewOlmAccount()
			store.PutAccount(acc)
			retrieved, err := store.GetAccount()
			if err != nil {
				t.Fatalf("Error retrieving account: %v", err)
			}
			if acc.IdentityKey() != retrieved.IdentityKey() {
				t.Errorf("Stored identity key %v, got %v", acc.IdentityKey(), retrieved.IdentityKey())
			}
			if acc.SigningKey() != retrieved.SigningKey() {
				t.Errorf("Stored signing key %v, got %v", acc.SigningKey(), retrieved.SigningKey())
			}
		})
	}
}

func TestValidateMessageIndex(t *testing.T) {
	stores, cleanup := getCryptoStores(t)
	defer cleanup()
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			acc := NewOlmAccount()
			if !store.ValidateMessageIndex(acc.IdentityKey(), "sess1", "event1", 0, 1000) {
				t.Error("First message not validated successfully")
			}
			if store.ValidateMessageIndex(acc.IdentityKey(), "sess1", "event1", 0, 1001) {
				t.Error("First message validated successfully after changing timestamp")
			}
			if store.ValidateMessageIndex(acc.IdentityKey(), "sess1", "event2", 0, 1000) {
				t.Error("First message validated successfully after changing event ID")
			}
			if !store.ValidateMessageIndex(acc.IdentityKey(), "sess1", "event1", 0, 1000) {
				t.Error("First message not validated successfully for a second time")
			}
		})
	}
}

func TestStoreOlmSession(t *testing.T) {
	stores, cleanup := getCryptoStores(t)
	defer cleanup()
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			if store.HasSession(olmSessID) {
				t.Error("Found Olm session before inserting it")
			}
			olmInternal, err := olm.SessionFromPickled([]byte(olmPickled), []byte("test"))
			if err != nil {
				t.Fatalf("Error creating internal Olm session: %v", err)
			}

			olmSess := OlmSession{
				id:       olmSessID,
				Internal: *olmInternal,
			}
			err = store.AddSession(olmSessID, &olmSess)
			if err != nil {
				t.Errorf("Error storing Olm session: %v", err)
			}
			if !store.HasSession(olmSessID) {
				t.Error("Not found Olm session after inserting it")
			}

			retrieved, err := store.GetLatestSession(olmSessID)
			if err != nil {
				t.Errorf("Failed retrieving Olm session: %v", err)
			}

			if retrieved.ID() != olmSessID {
				t.Errorf("Expected session ID to be %v, got %v", olmSessID, retrieved.ID())
			}
			if pickled := string(retrieved.Internal.Pickle([]byte("test"))); pickled != olmPickled {
				t.Error("Pickled Olm session does not match original")
			}
		})
	}
}

func TestStoreMegolmSession(t *testing.T) {
	stores, cleanup := getCryptoStores(t)
	defer cleanup()
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			acc := NewOlmAccount()

			internal, err := olm.InboundGroupSessionFromPickled([]byte(groupSession), []byte("test"))
			if err != nil {
				t.Fatalf("Error creating internal inbound group session: %v", err)
			}

			igs := &InboundGroupSession{
				Internal:   *internal,
				SigningKey: acc.SigningKey(),
				SenderKey:  acc.IdentityKey(),
				RoomID:     "room1",
			}

			err = store.PutGroupSession("room1", acc.IdentityKey(), igs.ID(), igs)
			if err != nil {
				t.Errorf("Error storing inbound group session: %v", err)
			}

			retrieved, err := store.GetGroupSession("room1", acc.IdentityKey(), igs.ID())
			if err != nil {
				t.Errorf("Error retrieving inbound group session: %v", err)
			}

			if pickled := string(retrieved.Internal.Pickle([]byte("test"))); pickled != groupSession {
				t.Error("Pickled inbound group session does not match original")
			}
		})
	}
}

func TestStoreOutboundMegolmSession(t *testing.T) {
	stores, cleanup := getCryptoStores(t)
	defer cleanup()
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			sess, err := store.GetOutboundGroupSession("room1")
			if sess != nil {
				t.Error("Got outbound session before inserting")
			}
			if err != nil {
				t.Errorf("Error retrieving outbound session: %v", err)
			}

			outbound := NewOutboundGroupSession("room1", nil)
			err = store.AddOutboundGroupSession(outbound)
			if err != nil {
				t.Errorf("Error inserting outbound session: %v", err)
			}

			sess, err = store.GetOutboundGroupSession("room1")
			if sess == nil {
				t.Error("Did not get outbound session after inserting")
			}
			if err != nil {
				t.Errorf("Error retrieving outbound session: %v", err)
			}

			err = store.RemoveOutboundGroupSession("room1")
			if err != nil {
				t.Errorf("Error deleting outbound session: %v", err)
			}

			sess, err = store.GetOutboundGroupSession("room1")
			if sess != nil {
				t.Error("Got outbound session after deleting")
			}
			if err != nil {
				t.Errorf("Error retrieving outbound session: %v", err)
			}
		})
	}
}

func TestStoreDevices(t *testing.T) {
	stores, cleanup := getCryptoStores(t)
	defer cleanup()
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			deviceMap := make(map[id.DeviceID]*DeviceIdentity)
			for i := 0; i < 17; i++ {
				iStr := strconv.Itoa(i)
				acc := NewOlmAccount()
				deviceMap[id.DeviceID("dev"+iStr)] = &DeviceIdentity{
					UserID:      "user1",
					DeviceID:    id.DeviceID("dev" + iStr),
					IdentityKey: acc.IdentityKey(),
					SigningKey:  acc.SigningKey(),
				}
			}
			err := store.PutDevices("user1", deviceMap)
			if err != nil {
				t.Errorf("Error string devices: %v", err)
			}
			devs, err := store.GetDevices("user1")
			if err != nil {
				t.Errorf("Error getting devices: %v", err)
			}
			if len(devs) != 17 {
				t.Errorf("Stored 17 devices, got back %v", len(devs))
			}
			if devs["dev0"].IdentityKey != deviceMap["dev0"].IdentityKey {
				t.Errorf("First device identity key does not match")
			}
			if devs["dev16"].IdentityKey != deviceMap["dev16"].IdentityKey {
				t.Errorf("Last device identity key does not match")
			}

			filtered := store.FilterTrackedUsers([]id.UserID{"user0", "user1", "user2"})
			if len(filtered) != 1 || filtered[0] != "user1" {
				t.Errorf("Expected to get 'user1' from filter, got %v", filtered)
			}
		})
	}
}
