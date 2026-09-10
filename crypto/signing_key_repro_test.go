package crypto

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/id"
)

// A client that logs out and logs back in under the same device ID gets a fresh
// Olm account. PutDevices must store the new signing key, not keep the old one.
func TestPutDevicesUpdatesSigningKeyAfterAccountReset(t *testing.T) {
	store := getCryptoStores(t)["sql"].(*SQLCryptoStore)
	ctx := context.Background()

	const userID = id.UserID("@user:example.org")
	const deviceID = id.DeviceID("DEVICE")

	put := func(identity id.IdentityKey, signing id.SigningKey) {
		t.Helper()
		require.NoError(t, store.PutDevices(ctx, userID, map[id.DeviceID]*id.Device{
			deviceID: {UserID: userID, DeviceID: deviceID, IdentityKey: identity, SigningKey: signing},
		}))
	}

	put("identity-1", "signing-1")

	// Logging out only flips deleted=true; the row stays.
	require.NoError(t, store.PutDevices(ctx, userID, map[id.DeviceID]*id.Device{}))

	put("identity-2", "signing-2")

	device, err := store.FindDeviceByKey(ctx, userID, "identity-2")
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, id.IdentityKey("identity-2"), device.IdentityKey)
	assert.Equal(t, id.SigningKey("signing-2"), device.SigningKey)
}
