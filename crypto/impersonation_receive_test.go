// Copyright (c) 2026 gchahcg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	testBotUser   = id.UserID("@bot:example.com")
	testGhostUser = id.UserID("@ghost:example.com")
	testRoom      = id.RoomID("room1")
)

// roomsStateStore is a state store that reports a fixed set of rooms as shared with every user.
type roomsStateStore struct {
	mockStateStore
	rooms []id.RoomID
}

func (s roomsStateStore) FindSharedRooms(context.Context, id.UserID) ([]id.RoomID, error) {
	return s.rooms, nil
}

func botDeviceFor(t *testing.T, mach *OlmMachine) *id.Device {
	t.Helper()
	return mach.OwnIdentity()
}

func TestValidateImpersonatableDevice(t *testing.T) {
	bot := newMachine(t, testBotUser)
	botDevice := botDeviceFor(t, bot)
	valid := func(t *testing.T) *mautrix.DeviceKeys {
		keys, err := bot.ImpersonatableDeviceKeys(testGhostUser)
		require.NoError(t, err)
		return keys
	}

	tests := []struct {
		name    string
		mutate  func(keys *mautrix.DeviceKeys)
		wantErr error
	}{
		{"valid", func(*mautrix.DeviceKeys) {}, nil},
		{"no impersonator", func(k *mautrix.DeviceKeys) { k.Impersonator = nil }, errNotImpersonatable},
		{"has algorithms", func(k *mautrix.DeviceKeys) { k.Algorithms = []id.Algorithm{id.AlgorithmMegolmV1} }, errImpersonatableHasKeys},
		{"has keys", func(k *mautrix.DeviceKeys) {
			k.Keys = mautrix.KeyMap{id.NewDeviceKeyID(id.KeyAlgorithmEd25519, k.DeviceID): "key"}
		}, errImpersonatableHasKeys},
		{"other impersonator user", func(k *mautrix.DeviceKeys) { k.Impersonator.UserID = "@mallory:example.com" }, errImpersonatorMismatch},
		{"other impersonator device", func(k *mautrix.DeviceKeys) { k.Impersonator.DeviceID = "OTHER" }, errImpersonatorMismatch},
		{"other embedded ed25519 key", func(k *mautrix.DeviceKeys) {
			k.Impersonator.Keys[id.NewDeviceKeyID(id.KeyAlgorithmEd25519, k.Impersonator.DeviceID)] = "other"
		}, errImpersonatorKeysMismatch},
		{"other embedded curve25519 key", func(k *mautrix.DeviceKeys) {
			k.Impersonator.Keys[id.NewDeviceKeyID(id.KeyAlgorithmCurve25519, k.Impersonator.DeviceID)] = "other"
		}, errImpersonatorKeysMismatch},
		{"tampered after signing", func(k *mautrix.DeviceKeys) { k.Impersonator.Algorithms = []id.Algorithm{"other"} }, errImpersonatableBadSignature},
		{"other owner after signing", func(k *mautrix.DeviceKeys) { k.UserID = "@mallory:example.com" }, errImpersonatableBadSignature},
		{"no signature", func(k *mautrix.DeviceKeys) { k.Signatures = nil }, errImpersonatableBadSignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := valid(t)
			tt.mutate(keys)
			err := validateImpersonatableDevice(keys, botDevice)
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

// The test vector was produced by matrix-rust-sdk, so this checks an implementation written independently of this
// one: a ghost device signed by a Rust bot device must be accepted. It was generated with the ignored test
// `test_print_test_vector` of matrix-sdk-crypto (feature experimental-msc4350) in the MSC4350 branch of
// https://github.com/matrix-org/matrix-rust-sdk (the ghost device and the bot device are in the test vector as printed).
func TestValidateImpersonatableDeviceFromRust(t *testing.T) {
	data, err := os.ReadFile("testdata/msc4350_rust_ghost_device.json")
	require.NoError(t, err)
	var vector struct {
		BotUserID     id.UserID           `json:"bot_user_id"`
		BotDeviceID   id.DeviceID         `json:"bot_device_id"`
		BotDeviceKeys *mautrix.DeviceKeys `json:"bot_device_keys"`
		GhostDevice   *mautrix.DeviceKeys `json:"ghost_device"`
	}
	require.NoError(t, json.Unmarshal(data, &vector))

	// The bot device itself is valid, as validateDevice requires before it is stored.
	botDevice, err := (&OlmMachine{}).validateDevice(vector.BotUserID, vector.BotDeviceID, *vector.BotDeviceKeys, nil)
	require.NoError(t, err)

	require.NoError(t, validateImpersonatableDevice(vector.GhostDevice, botDevice))

	vector.GhostDevice.Impersonator.Algorithms = nil
	assert.ErrorIs(t, validateImpersonatableDevice(vector.GhostDevice, botDevice), errImpersonatableBadSignature)
}

// impersonationFixture has a bridge bot machine that sent a message encrypted with a megolm session that a
// receiving machine has, so the message can be presented as sent by any user.
type impersonationFixture struct {
	bot, receiver *OlmMachine
	botDevice     *id.Device
	content       *event.EncryptedEventContent
}

func newImpersonationFixture(t *testing.T) *impersonationFixture {
	t.Helper()
	ctx := context.Background()
	bot := newMachine(t, testBotUser)
	receiver := newMachine(t, "@receiver:example.com")
	receiver.StateStore = roomsStateStore{rooms: []id.RoomID{testRoom}}
	// The receiver's copy of the bot's device, which isn't verified manually (a machine's own device is).
	botDevice := botDeviceFor(t, bot)
	botDevice.Trust = id.TrustStateUnset

	require.NoError(t, receiver.CryptoStore.PutDevices(ctx, testBotUser, map[id.DeviceID]*id.Device{botDevice.DeviceID: botDevice}))

	session, err := bot.newOutboundGroupSession(ctx, testRoom)
	require.NoError(t, err)
	session.Shared = true
	require.NoError(t, bot.CryptoStore.AddOutboundGroupSession(ctx, session))
	shareContent := session.ShareContent()
	inbound, err := NewInboundGroupSession(botDevice.IdentityKey, botDevice.SigningKey, testRoom, shareContent.AsRoomKey().SessionKey, 0, 0, nil, false)
	require.NoError(t, err)
	require.NoError(t, receiver.CryptoStore.PutGroupSession(ctx, inbound))

	content, err := bot.EncryptMegolmEvent(ctx, testRoom, event.EventMessage, map[string]string{"msgtype": "m.text", "body": "hello from the ghost"})
	require.NoError(t, err)

	return &impersonationFixture{bot: bot, receiver: receiver, botDevice: botDevice, content: content}
}

func (f *impersonationFixture) decrypt(t *testing.T, sender id.UserID) *event.Event {
	t.Helper()
	decrypted, err := f.receiver.DecryptMegolmEvent(context.Background(), &event.Event{
		Type:    event.EventEncrypted,
		ID:      "$event",
		RoomID:  testRoom,
		Sender:  sender,
		Content: event.Content{Parsed: f.content},
	})
	require.NoError(t, err)
	return decrypted
}

// crossSignBot makes the receiver see the bot's device as signed by the bot's self-signing key.
func (f *impersonationFixture) crossSignBot(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	msk, err := olm.NewPKSigning()
	require.NoError(t, err)
	ssk, err := olm.NewPKSigning()
	require.NoError(t, err)
	store := f.receiver.CryptoStore
	require.NoError(t, store.PutCrossSigningKey(ctx, testBotUser, id.XSUsageMaster, msk.PublicKey()))
	require.NoError(t, store.PutCrossSigningKey(ctx, testBotUser, id.XSUsageSelfSigning, ssk.PublicKey()))
	require.NoError(t, store.PutSignature(ctx, testBotUser, ssk.PublicKey(), testBotUser, msk.PublicKey(), "sig"))
	require.NoError(t, store.PutSignature(ctx, testBotUser, f.botDevice.SigningKey, testBotUser, ssk.PublicKey(), "sig"))
}

// setGhostDevice makes the receiver know the given impersonatable device for the ghost.
func (f *impersonationFixture) setGhostDevice(keys *mautrix.DeviceKeys) {
	f.receiver.impersonatable.replace(testGhostUser, []*mautrix.DeviceKeys{keys})
}

func (f *impersonationFixture) ghostKeys(t *testing.T) *mautrix.DeviceKeys {
	t.Helper()
	keys, err := f.bot.ImpersonatableDeviceKeys(testGhostUser)
	require.NoError(t, err)
	return keys
}

func TestDecryptImpersonatedMessage(t *testing.T) {
	f := newImpersonationFixture(t)

	// Without an impersonatable device, the message isn't from a known device of the sender.
	assert.Equal(t, id.TrustStateUnknownDevice, f.decrypt(t, testGhostUser).Mautrix.TrustState)

	// With one, but the bot's device isn't cross-signed, it still isn't trusted.
	f.setGhostDevice(f.ghostKeys(t))
	assert.Equal(t, id.TrustStateUnknownDevice, f.decrypt(t, testGhostUser).Mautrix.TrustState)

	// Once the bot's device is cross-signed, the message is trusted as the bot's device is, and appears to come
	// from a device of the ghost.
	f.crossSignBot(t)
	decrypted := f.decrypt(t, testGhostUser)
	assert.Equal(t, id.TrustStateCrossSignedTOFU, decrypted.Mautrix.TrustState)
	require.NotNil(t, decrypted.Mautrix.TrustSource)
	assert.Equal(t, testGhostUser, decrypted.Mautrix.TrustSource.UserID)
	assert.Equal(t, f.botDevice.DeviceID, decrypted.Mautrix.TrustSource.DeviceID)
	assert.True(t, decrypted.Mautrix.WasEncrypted)

	// Another user the bot has no device for is still not trusted.
	assert.Equal(t, id.TrustStateUnknownDevice, f.decrypt(t, "@other:example.com").Mautrix.TrustState)
}

func TestDecryptImpersonatedMessageNeedsImpersonatorInRoom(t *testing.T) {
	f := newImpersonationFixture(t)
	f.crossSignBot(t)
	f.setGhostDevice(f.ghostKeys(t))
	assert.Equal(t, id.TrustStateCrossSignedTOFU, f.decrypt(t, testGhostUser).Mautrix.TrustState)

	f.receiver.StateStore = roomsStateStore{rooms: []id.RoomID{"another room"}}
	assert.Equal(t, id.TrustStateUnknownDevice, f.decrypt(t, testGhostUser).Mautrix.TrustState)
}

func TestDecryptImpersonatedMessageRejectsInvalidDevices(t *testing.T) {
	f := newImpersonationFixture(t)
	f.crossSignBot(t)

	tampered := f.ghostKeys(t)
	tampered.Impersonator.Algorithms = []id.Algorithm{"other"}
	f.setGhostDevice(tampered)
	assert.Equal(t, id.TrustStateUnknownDevice, f.decrypt(t, testGhostUser).Mautrix.TrustState)

	// A device signed by someone else who claims to be the bot's device.
	other := newMachine(t, testBotUser)
	forged, err := other.ImpersonatableDeviceKeys(testGhostUser)
	require.NoError(t, err)
	f.setGhostDevice(forged)
	assert.Equal(t, id.TrustStateUnknownDevice, f.decrypt(t, testGhostUser).Mautrix.TrustState)

	f.setGhostDevice(f.ghostKeys(t))
	assert.Equal(t, id.TrustStateCrossSignedTOFU, f.decrypt(t, testGhostUser).Mautrix.TrustState)
}

func TestDecryptImpersonatedMessageFromGhostWithCrossSigningKeys(t *testing.T) {
	ctx := context.Background()
	f := newImpersonationFixture(t)
	f.crossSignBot(t)

	ghostMSK, err := olm.NewPKSigning()
	require.NoError(t, err)
	ghostSSK, err := olm.NewPKSigning()
	require.NoError(t, err)
	require.NoError(t, f.receiver.CryptoStore.PutCrossSigningKey(ctx, testGhostUser, id.XSUsageMaster, ghostMSK.PublicKey()))
	require.NoError(t, f.receiver.CryptoStore.PutCrossSigningKey(ctx, testGhostUser, id.XSUsageSelfSigning, ghostSSK.PublicKey()))

	// The ghost has cross-signing keys, so the bot's signature alone isn't enough.
	keys := f.ghostKeys(t)
	f.setGhostDevice(keys)
	assert.Equal(t, id.TrustStateUnknownDevice, f.decrypt(t, testGhostUser).Mautrix.TrustState)

	// Once the ghost's self-signing key has signed the device, it is.
	signature, err := ghostSSK.SignJSON(keys)
	require.NoError(t, err)
	keys.Signatures[testGhostUser] = map[id.KeyID]string{id.NewKeyID(id.KeyAlgorithmEd25519, ghostSSK.PublicKey().String()): signature}
	f.setGhostDevice(keys)
	assert.Equal(t, id.TrustStateCrossSignedTOFU, f.decrypt(t, testGhostUser).Mautrix.TrustState)

	// The bot's signature is still checked.
	valid, err := signatures.VerifySignatureJSON(keys, testBotUser, f.botDevice.DeviceID.String(), f.botDevice.SigningKey)
	require.NoError(t, err)
	assert.True(t, valid)
}

// FetchKeys must not try to store an impersonatable device as a regular device, but remember it for later.
func TestFetchKeysKeepsImpersonatableDevices(t *testing.T) {
	ctx := context.Background()
	bot := newMachine(t, testBotUser)
	ghostKeys, err := bot.ImpersonatableDeviceKeys(testGhostUser)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_keys": map[id.UserID]map[id.DeviceID]any{
				testGhostUser: {ghostKeys.DeviceID: ghostKeys},
			},
		})
	}))
	defer server.Close()

	receiver := newMachine(t, "@receiver:example.com")
	receiver.Client.HomeserverURL, _ = receiver.Client.HomeserverURL.Parse(server.URL)

	data, err := receiver.FetchKeys(ctx, []id.UserID{testGhostUser}, true)
	require.NoError(t, err)
	assert.Empty(t, data[testGhostUser], "an impersonatable device must not be returned as a regular device")
	stored, err := receiver.CryptoStore.GetDevices(ctx, testGhostUser)
	require.NoError(t, err)
	assert.Empty(t, stored)

	remembered := receiver.impersonatable.get(testGhostUser)
	require.Len(t, remembered, 1)
	assert.Equal(t, ghostKeys.DeviceID, remembered[0].DeviceID)
	assert.NotNil(t, remembered[0].Impersonator)
}
