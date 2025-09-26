// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/rs/zerolog"
	globallog "github.com/rs/zerolog/log" // zerolog-allow-global-log
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mockserver"
)

func randomDeviceCount(r *rand.Rand) int {
	k := 1
	for k < 10 && r.IntN(3) > 0 {
		k++
	}
	return k
}

func BenchmarkOlmMachine_ShareGroupSession(b *testing.B) {
	globallog.Logger = zerolog.Nop()
	server := mockserver.Create(b)
	server.PopOTKs = false
	server.MemoryStore = false
	var i int
	var shareTargets []id.UserID
	r := rand.New(rand.NewPCG(293, 0))
	var totalDeviceCount int
	for i = 1; i < 1000; i++ {
		userID := id.UserID(fmt.Sprintf("@user%d:localhost", i))
		deviceCount := randomDeviceCount(r)
		for j := 0; j < deviceCount; j++ {
			client, _ := server.Login(b, nil, userID, id.DeviceID(fmt.Sprintf("u%d_d%d", i, j)))
			mach := client.Crypto.(*cryptohelper.CryptoHelper).Machine()
			keysCache, err := mach.GenerateCrossSigningKeys()
			require.NoError(b, err)
			err = mach.PublishCrossSigningKeys(context.TODO(), keysCache, nil)
			require.NoError(b, err)
		}
		totalDeviceCount += deviceCount
		shareTargets = append(shareTargets, userID)
	}
	for b.Loop() {
		client, _ := server.Login(b, nil, id.UserID(fmt.Sprintf("@benchuser%d:localhost", i)), id.DeviceID(fmt.Sprintf("u%d_d1", i)))
		mach := client.Crypto.(*cryptohelper.CryptoHelper).Machine()
		keysCache, err := mach.GenerateCrossSigningKeys()
		require.NoError(b, err)
		err = mach.PublishCrossSigningKeys(context.TODO(), keysCache, nil)
		require.NoError(b, err)
		err = mach.ShareGroupSession(context.TODO(), "!room:localhost", shareTargets)
		require.NoError(b, err)
		i++
	}
	fmt.Println(totalDeviceCount, "devices total")
}
