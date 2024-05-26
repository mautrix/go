// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package hicli contains a highly opinionated high-level framework for developing instant messaging clients on Matrix.
package hicli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/hicli/database"
	"maunium.net/go/mautrix/id"
)

type HiClient struct {
	DB          *database.Database
	Account     *database.Account
	Client      *mautrix.Client
	Crypto      *crypto.OlmMachine
	CryptoStore *crypto.SQLCryptoStore
	ClientStore *database.ClientStateStore
	Log         zerolog.Logger

	Verified bool

	KeyBackupVersion id.KeyBackupVersion
	KeyBackupKey     *backup.MegolmBackupKey

	firstSyncReceived bool
	syncingID         int
	syncLock          sync.Mutex
	encryptLock       sync.Mutex

	requestQueueWakeup chan struct{}
}

func New(rawDB *dbutil.Database, log zerolog.Logger, pickleKey []byte) *HiClient {
	rawDB.Owner = "hicli"
	rawDB.IgnoreForeignTables = true
	db := database.New(rawDB)
	db.Log = dbutil.ZeroLogger(log.With().Str("db_section", "hicli").Logger())
	c := &HiClient{
		DB:  db,
		Log: log,

		requestQueueWakeup: make(chan struct{}, 1),
	}
	c.ClientStore = &database.ClientStateStore{Database: db}
	c.Client = &mautrix.Client{
		UserAgent: mautrix.DefaultUserAgent,
		Client: &http.Client{
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
				// This needs to be relatively high to allow initial syncs
				ResponseHeaderTimeout: 180 * time.Second,
				ForceAttemptHTTP2:     true,
			},
			Timeout: 180 * time.Second,
		},
		Syncer:     (*hiSyncer)(c),
		Store:      (*hiStore)(c),
		StateStore: c.ClientStore,
		Log:        log.With().Str("component", "mautrix client").Logger(),
	}
	c.CryptoStore = crypto.NewSQLCryptoStore(rawDB, dbutil.ZeroLogger(log.With().Str("db_section", "crypto").Logger()), "", "", pickleKey)
	cryptoLog := log.With().Str("component", "crypto").Logger()
	c.Crypto = crypto.NewOlmMachine(c.Client, &cryptoLog, c.CryptoStore, c.ClientStore)
	c.Crypto.SessionReceived = c.handleReceivedMegolmSession
	c.Crypto.DisableRatchetTracking = true
	c.Crypto.DisableDecryptKeyFetching = true
	c.Client.Crypto = (*hiCryptoHelper)(c)
	return c
}

func (h *HiClient) IsLoggedIn() bool {
	return h.Account != nil
}

func (h *HiClient) Start(ctx context.Context, userID id.UserID) error {
	err := h.DB.Upgrade(ctx)
	if err != nil {
		return fmt.Errorf("failed to upgrade hicli db: %w", err)
	}
	err = h.CryptoStore.DB.Upgrade(ctx)
	if err != nil {
		return fmt.Errorf("failed to upgrade crypto db: %w", err)
	}
	account, err := h.DB.Account.Get(ctx, userID)
	if err != nil {
		return err
	}
	if account != nil {
		zerolog.Ctx(ctx).Debug().Stringer("user_id", account.UserID).Msg("Preparing client with existing credentials")
		h.Account = account
		h.CryptoStore.AccountID = account.UserID.String()
		h.CryptoStore.DeviceID = account.DeviceID
		h.Client.UserID = account.UserID
		h.Client.DeviceID = account.DeviceID
		h.Client.AccessToken = account.AccessToken
		h.Client.HomeserverURL, err = url.Parse(account.HomeserverURL)
		if err != nil {
			return err
		}
		err = h.Crypto.Load(ctx)
		if err != nil {
			return fmt.Errorf("failed to load olm machine: %w", err)
		}

		h.Verified, err = h.checkIsCurrentDeviceVerified(ctx)
		if err != nil {
			return err
		}
		zerolog.Ctx(ctx).Debug().Bool("verified", h.Verified).Msg("Checked current device verification status")
		if h.Verified {
			err = h.loadPrivateKeys(ctx)
			if err != nil {
				return err
			}
			go h.Sync()
			go h.RunRequestQueue(ctx)
		}
	}
	return nil
}

func (h *HiClient) Sync() {
	h.Client.StopSync()
	h.syncLock.Lock()
	defer h.syncLock.Unlock()
	h.syncingID++
	syncingID := h.syncingID
	log := h.Log.With().
		Str("action", "sync").
		Int("sync_id", syncingID).
		Logger()
	ctx := log.WithContext(context.Background())
	log.Info().Msg("Starting syncing")
	err := h.Client.SyncWithContext(ctx)
	if err != nil {
		log.Err(err).Msg("Fatal error in syncer")
	} else {
		log.Info().Msg("Syncing stopped")
	}
}
