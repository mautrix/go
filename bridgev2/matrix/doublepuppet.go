// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/id"
)

type doublePuppetUtil struct {
	br *Connector

	discoveryCache     map[string]string
	discoveryCacheLock sync.Mutex
}

func newDoublePuppetUtil(br *Connector) *doublePuppetUtil {
	return &doublePuppetUtil{
		br:             br,
		discoveryCache: make(map[string]string),
	}
}

func (dp *doublePuppetUtil) newClient(ctx context.Context, mxid id.UserID, accessToken string) (*mautrix.Client, error) {
	_, homeserver, err := mxid.Parse()
	if err != nil {
		return nil, err
	}
	homeserverURL, found := dp.br.Config.DoublePuppet.Servers[homeserver]
	if !found {
		if homeserver == dp.br.AS.HomeserverDomain {
			homeserverURL = ""
		} else if dp.br.Config.DoublePuppet.AllowDiscovery {
			dp.discoveryCacheLock.Lock()
			defer dp.discoveryCacheLock.Unlock()
			if homeserverURL, found = dp.discoveryCache[homeserver]; !found {
				resp, err := mautrix.DiscoverClientAPI(ctx, homeserver)
				if err != nil {
					return nil, fmt.Errorf("failed to find homeserver URL for %s: %v", homeserver, err)
				}
				homeserverURL = resp.Homeserver.BaseURL
				dp.discoveryCache[homeserver] = homeserverURL
				zerolog.Ctx(ctx).Debug().
					Str("homeserver", homeserver).
					Str("url", homeserverURL).
					Str("user_id", mxid.String()).
					Msg("Discovered URL to enable double puppeting for user")
			}
		} else {
			return nil, fmt.Errorf("double puppeting from %s is not allowed", homeserver)
		}
	}
	return dp.br.AS.NewExternalMautrixClient(mxid, accessToken, homeserverURL)
}

func (dp *doublePuppetUtil) newIntent(ctx context.Context, mxid id.UserID, accessToken string) (*appservice.IntentAPI, error) {
	client, err := dp.newClient(ctx, mxid, accessToken)
	if err != nil {
		return nil, err
	}

	ia := dp.br.AS.NewIntentAPI("custom")
	ia.Client = client
	ia.Localpart, _, _ = mxid.Parse()
	ia.UserID = mxid
	ia.IsCustomPuppet = true
	return ia, nil
}

var (
	ErrMismatchingMXID = errors.New("whoami result does not match custom mxid")
	ErrNoAccessToken   = errors.New("no access token provided")
	ErrNoMXID          = errors.New("no mxid provided")
)

const useConfigASToken = "appservice-config"
const asTokenModePrefix = "as_token:"

func (dp *doublePuppetUtil) Setup(ctx context.Context, mxid id.UserID, savedAccessToken string) (intent *appservice.IntentAPI, newAccessToken string, err error) {
	if len(mxid) == 0 {
		err = ErrNoMXID
		return
	}
	_, homeserver, _ := mxid.Parse()
	loginSecret, hasSecret := dp.br.Config.DoublePuppet.Secrets[homeserver]
	if hasSecret && strings.HasPrefix(loginSecret, asTokenModePrefix) {
		intent, err = dp.newIntent(ctx, mxid, strings.TrimPrefix(loginSecret, asTokenModePrefix))
		if err != nil {
			return
		}
		intent.SetAppServiceUserID = true
		if savedAccessToken != useConfigASToken {
			var resp *mautrix.RespWhoami
			resp, err = intent.Whoami(ctx)
			if err == nil && resp.UserID != mxid {
				err = ErrMismatchingMXID
			}
		}
		return intent, useConfigASToken, err
	} else if savedAccessToken == "" || savedAccessToken == useConfigASToken {
		err = ErrNoAccessToken
		return
	}
	intent, err = dp.newIntent(ctx, mxid, savedAccessToken)
	if err != nil {
		return
	}
	var resp *mautrix.RespWhoami
	resp, err = intent.Whoami(ctx)
	if err == nil {
		if resp.UserID != mxid {
			err = ErrMismatchingMXID
		} else {
			newAccessToken = savedAccessToken
		}
	}
	return
}
