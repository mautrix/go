// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"database/sql"
	"strconv"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

const olmSessID = "sJlikQQKXp7UQjmS9/lyZCNUVJ2AmKyHbufPBaC7tpk"
const olmPickled = "L6cdv3JYO9OzhXbcjNSwl7ldN5bDvwmGyin+hISePETE6bO71DIlhqTC9YIhg21RDqRPH2HNl1MCyCw0hEXICWQyeJ9S7JLie" +
	"5PYxhqSSaTYaybvlvw34jvuSgEx0iotM6WNuWu5ocrsOo5Ye/3Nz7lBvxaw2rpS0jZnn7eV1n9GbINZk4YEVWrHOn7OxYfaGECJHDeAk/ameStiy" +
	"o1Gru0a/cmR0O3oKMyYnlXir0jS7oETMCsWk59GeVlz++j4aK0FK4g8/3fCMmLDXSatFjE9hoWDmeRwal58Y+XwX76Te/PiWtrFrinvCDEQJcZTa" +
	"qcCwp6sZrgLbmfBUBb0zJCogCmYw8m2"
const groupSession = "9ZbsRqJuETbjnxPpKv29n3dubP/m5PSLbr9I9CIWS2O86F/Og1JZXhqT+4fA5tovoPfdpk5QLh7PfDyjmgOcO9sSA37maJyzCy6Ap+uBZLAXp6VLJ0mjSvxi+PAbzGKDMqpn+pa+oeEIH6SFPG/2GGDSRoXVi5fttAClCIoav5RflWiMypKqnQRfkZR2Gx8glOaBiTzAd7m0X6XGfYIPol41JUIHfBLuJBfXQ0Uu5GScV4eKUWdJP2J6zzC2Hx8cZAhiBBzAza0CbGcnUK+YJXMYaJg92HiIo++l317LlsYUJ/P+gKOLafYR9/l8bAzxH7j5s31PnRs7mD1Bl6G1LFM+dPsGXUOLx6PlvlTlYYM/opai0uKKzT0Wk6zPoq9fN/smlXEPBtKlw2fqcytL4gOF0MrBPEca"

func getCryptoStores(t *testing.T) map[string]Store {
	rawDB, err := sql.Open("sqlite3", ":memory:?_busy_timeout=5000")
	require.NoError(t, err, "Error opening raw database")
	db, err := dbutil.NewWithDB(rawDB, "sqlite3")
	require.NoError(t, err, "Error creating database wrapper")
	sqlStore := NewSQLCryptoStore(db, nil, "accid", id.DeviceID("dev"), []byte("test"))
	err = sqlStore.DB.Upgrade(context.TODO())
	require.NoError(t, err, "Error upgrading database")

	gobStore := NewMemoryStore(nil)

	return map[string]Store{
		"sql": sqlStore,
		"gob": gobStore,
	}
}

func TestPutNextBatch(t *testing.T) {
	stores := getCryptoStores(t)
	store := stores["sql"].(*SQLCryptoStore)
	store.PutNextBatch(context.Background(), "batch1")

	batch, err := store.GetNextBatch(context.Background())
	require.NoError(t, err, "Error retrieving next batch")
	assert.Equal(t, "batch1", batch)
}

func TestPutAccount(t *testing.T) {
	stores := getCryptoStores(t)
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			acc := NewOlmAccount()
			store.PutAccount(context.TODO(), acc)
			retrieved, err := store.GetAccount(context.TODO())
			require.NoError(t, err, "Error retrieving account")
			assert.Equal(t, acc.IdentityKey(), retrieved.IdentityKey(), "Identity key does not match")
			assert.Equal(t, acc.SigningKey(), retrieved.SigningKey(), "Signing key does not match")
		})
	}
}

func TestValidateMessageIndex(t *testing.T) {
	stores := getCryptoStores(t)
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			acc := NewOlmAccount()

			// Validating without event ID and timestamp before we have them should work
			ok, err := store.ValidateMessageIndex(context.TODO(), acc.IdentityKey(), "sess1", "", 0, 0)
			require.NoError(t, err, "Error validating message index")
			assert.True(t, ok, "First message validation should be valid")

			// First message should validate successfully
			ok, err = store.ValidateMessageIndex(context.TODO(), acc.IdentityKey(), "sess1", "event1", 0, 1000)
			require.NoError(t, err, "Error validating message index")
			assert.True(t, ok, "First message validation should be valid")

			// Edit the timestamp and ensure validate fails
			ok, err = store.ValidateMessageIndex(context.TODO(), acc.IdentityKey(), "sess1", "event1", 0, 1001)
			require.NoError(t, err, "Error validating message index after timestamp change")
			assert.False(t, ok, "First message validation should fail after timestamp change")

			// Edit the event ID and ensure validate fails
			ok, err = store.ValidateMessageIndex(context.TODO(), acc.IdentityKey(), "sess1", "event2", 0, 1000)
			require.NoError(t, err, "Error validating message index after event ID change")
			assert.False(t, ok, "First message validation should fail after event ID change")

			// Validate again with the original parameters and ensure that it still passes
			ok, err = store.ValidateMessageIndex(context.TODO(), acc.IdentityKey(), "sess1", "event1", 0, 1000)
			require.NoError(t, err, "Error validating message index")
			assert.True(t, ok, "First message validation should be valid")

			// Validating without event ID and timestamp must fail if we already know them
			ok, err = store.ValidateMessageIndex(context.TODO(), acc.IdentityKey(), "sess1", "", 0, 0)
			require.NoError(t, err, "Error validating message index")
			assert.False(t, ok, "First message validation should be invalid")
		})
	}
}

func TestStoreOlmSession(t *testing.T) {
	stores := getCryptoStores(t)
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			require.False(t, store.HasSession(context.TODO(), olmSessID), "Found Olm session before inserting it")

			olmInternal, err := olm.SessionFromPickled([]byte(olmPickled), []byte("test"))
			require.NoError(t, err, "Error creating internal Olm session")

			olmSess := OlmSession{
				id:       olmSessID,
				Internal: olmInternal,
			}
			err = store.AddSession(context.TODO(), olmSessID, &olmSess)
			require.NoError(t, err, "Error storing Olm session")
			assert.True(t, store.HasSession(context.TODO(), olmSessID), "Olm session not found after inserting it")

			retrieved, err := store.GetLatestSession(context.TODO(), olmSessID)
			require.NoError(t, err, "Error retrieving Olm session")
			assert.EqualValues(t, olmSessID, retrieved.ID())

			pickled, err := retrieved.Internal.Pickle([]byte("test"))
			require.NoError(t, err, "Error pickling Olm session")
			assert.EqualValues(t, pickled, olmPickled, "Pickled Olm session does not match original")
		})
	}
}

func TestStoreMegolmSession(t *testing.T) {
	stores := getCryptoStores(t)
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			acc := NewOlmAccount()

			internal, err := olm.InboundGroupSessionFromPickled([]byte(groupSession), []byte("test"))
			require.NoError(t, err, "Error creating internal inbound group session")

			igs := &InboundGroupSession{
				Internal:   internal,
				SigningKey: acc.SigningKey(),
				SenderKey:  acc.IdentityKey(),
				RoomID:     "room1",
			}

			err = store.PutGroupSession(context.TODO(), igs)
			require.NoError(t, err, "Error storing inbound group session")

			retrieved, err := store.GetGroupSession(context.TODO(), "room1", igs.ID())
			require.NoError(t, err, "Error retrieving inbound group session")

			pickled, err := retrieved.Internal.Pickle([]byte("test"))
			require.NoError(t, err, "Error pickling inbound group session")
			assert.EqualValues(t, pickled, groupSession, "Pickled inbound group session does not match original")
		})
	}
}

func TestStoreOutboundMegolmSession(t *testing.T) {
	stores := getCryptoStores(t)
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			sess, err := store.GetOutboundGroupSession(context.TODO(), "room1")
			require.NoError(t, err, "Error retrieving outbound session")
			require.Nil(t, sess, "Got outbound session before inserting")

			outbound, err := NewOutboundGroupSession("room1", nil)
			require.NoError(t, err)
			err = store.AddOutboundGroupSession(context.TODO(), outbound)
			require.NoError(t, err, "Error inserting outbound session")

			sess, err = store.GetOutboundGroupSession(context.TODO(), "room1")
			require.NoError(t, err, "Error retrieving outbound session")
			assert.NotNil(t, sess, "Did not get outbound session after inserting")

			err = store.RemoveOutboundGroupSession(context.TODO(), "room1")
			require.NoError(t, err, "Error deleting outbound session")

			sess, err = store.GetOutboundGroupSession(context.TODO(), "room1")
			require.NoError(t, err, "Error retrieving outbound session after deletion")
			assert.Nil(t, sess, "Got outbound session after deleting")
		})
	}
}

func TestStoreOutboundMegolmSessionSharing(t *testing.T) {
	stores := getCryptoStores(t)

	resetDevice := func() *id.Device {
		acc := NewOlmAccount()
		return &id.Device{
			UserID:      "user1",
			DeviceID:    id.DeviceID("dev1"),
			IdentityKey: acc.IdentityKey(),
			SigningKey:  acc.SigningKey(),
		}
	}

	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			device := resetDevice()
			err := store.PutDevice(context.TODO(), "user1", device)
			require.NoError(t, err, "Error storing device")

			shared, err := store.IsOutboundGroupSessionShared(context.TODO(), device.UserID, device.IdentityKey, "session1")
			require.NoError(t, err, "Error checking if outbound group session is shared")
			assert.False(t, shared, "Outbound group session should not be shared initially")

			err = store.MarkOutboundGroupSessionShared(context.TODO(), device.UserID, device.IdentityKey, "session1")
			require.NoError(t, err, "Error marking outbound group session as shared")

			shared, err = store.IsOutboundGroupSessionShared(context.TODO(), device.UserID, device.IdentityKey, "session1")
			require.NoError(t, err, "Error checking if outbound group session is shared")
			assert.True(t, shared, "Outbound group session should be shared after marking it as such")

			device = resetDevice()
			err = store.PutDevice(context.TODO(), "user1", device)
			require.NoError(t, err, "Error storing device after resetting")

			shared, err = store.IsOutboundGroupSessionShared(context.TODO(), device.UserID, device.IdentityKey, "session1")
			require.NoError(t, err, "Error checking if outbound group session is shared")
			assert.False(t, shared, "Outbound group session should not be shared after resetting device")
		})
	}
}

func TestStoreDevices(t *testing.T) {
	devicesToCreate := 17
	stores := getCryptoStores(t)
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			outdated, err := store.GetOutdatedTrackedUsers(context.TODO())
			require.NoError(t, err, "Error filtering tracked users")
			assert.Empty(t, outdated, "Expected no outdated tracked users initially")

			deviceMap := make(map[id.DeviceID]*id.Device)
			for i := 0; i < devicesToCreate; i++ {
				iStr := strconv.Itoa(i)
				acc := NewOlmAccount()
				deviceMap[id.DeviceID("dev"+iStr)] = &id.Device{
					UserID:      "user1",
					DeviceID:    id.DeviceID("dev" + iStr),
					IdentityKey: acc.IdentityKey(),
					SigningKey:  acc.SigningKey(),
				}
			}
			err = store.PutDevices(context.TODO(), "user1", deviceMap)
			require.NoError(t, err, "Error storing devices")
			devs, err := store.GetDevices(context.TODO(), "user1")
			require.NoError(t, err, "Error getting devices")
			assert.Len(t, devs, devicesToCreate, "Expected to get %d devices back", devicesToCreate)
			assert.Equal(t, deviceMap, devs, "Stored devices do not match retrieved devices")

			filtered, err := store.FilterTrackedUsers(context.TODO(), []id.UserID{"user0", "user1", "user2"})
			require.NoError(t, err, "Error filtering tracked users")
			assert.Equal(t, []id.UserID{"user1"}, filtered, "Expected to get 'user1' from filter")

			outdated, err = store.GetOutdatedTrackedUsers(context.TODO())
			require.NoError(t, err, "Error filtering tracked users")
			assert.Empty(t, outdated, "Expected no outdated tracked users after initial storage")

			err = store.MarkTrackedUsersOutdated(context.TODO(), []id.UserID{"user0", "user1"})
			require.NoError(t, err, "Error marking tracked users outdated")

			outdated, err = store.GetOutdatedTrackedUsers(context.TODO())
			require.NoError(t, err, "Error filtering tracked users")
			assert.Equal(t, []id.UserID{"user1"}, outdated, "Expected 'user1' to be marked as outdated")

			err = store.PutDevices(context.TODO(), "user1", deviceMap)
			require.NoError(t, err, "Error storing devices again")

			outdated, err = store.GetOutdatedTrackedUsers(context.TODO())
			require.NoError(t, err, "Error filtering tracked users")
			assert.Empty(t, outdated, "Expected no outdated tracked users after re-storing devices")
		})
	}
}

func TestStoreSecrets(t *testing.T) {
	stores := getCryptoStores(t)
	for storeName, store := range stores {
		t.Run(storeName, func(t *testing.T) {
			storedSecret := "trustno1"
			err := store.PutSecret(context.TODO(), id.SecretMegolmBackupV1, storedSecret)
			require.NoError(t, err, "Error storing secret")

			secret, err := store.GetSecret(context.TODO(), id.SecretMegolmBackupV1)
			require.NoError(t, err, "Error retrieving secret")
			assert.Equal(t, storedSecret, secret, "Retrieved secret does not match stored secret")
		})
	}
}
