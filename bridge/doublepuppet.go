// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridge

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/appservice"
	"github.com/element-hq/mautrix-go/id"
)

type doublePuppetUtil struct {
	br  *Bridge
	log zerolog.Logger
}

func (dp *doublePuppetUtil) newClient(ctx context.Context, mxid id.UserID, accessToken string) (*mautrix.Client, error) {
	_, homeserver, err := mxid.Parse()
	if err != nil {
		return nil, err
	}
	homeserverURL, found := dp.br.Config.Bridge.GetDoublePuppetConfig().ServerMap[homeserver]
	if !found {
		if homeserver == dp.br.AS.HomeserverDomain {
			homeserverURL = ""
		} else if dp.br.Config.Bridge.GetDoublePuppetConfig().AllowDiscovery {
			resp, err := mautrix.DiscoverClientAPI(ctx, homeserver)
			if err != nil {
				return nil, fmt.Errorf("failed to find homeserver URL for %s: %v", homeserver, err)
			}
			homeserverURL = resp.Homeserver.BaseURL
			dp.log.Debug().
				Str("homeserver", homeserver).
				Str("url", homeserverURL).
				Str("user_id", mxid.String()).
				Msg("Discovered URL to enable double puppeting for user")
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

func (dp *doublePuppetUtil) autoLogin(ctx context.Context, mxid id.UserID, loginSecret string) (string, error) {
	dp.log.Debug().Str("user_id", mxid.String()).Msg("Logging into user account with shared secret")
	client, err := dp.newClient(ctx, mxid, "")
	if err != nil {
		return "", fmt.Errorf("failed to create mautrix client to log in: %v", err)
	}
	bridgeName := fmt.Sprintf("%s Bridge", dp.br.ProtocolName)
	req := mautrix.ReqLogin{
		Identifier:               mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: string(mxid)},
		DeviceID:                 id.DeviceID(bridgeName),
		InitialDeviceDisplayName: bridgeName,
	}
	if loginSecret == "appservice" {
		client.AccessToken = dp.br.AS.Registration.AppToken
		req.Type = mautrix.AuthTypeAppservice
	} else {
		loginFlows, err := client.GetLoginFlows(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to get supported login flows: %w", err)
		}
		mac := hmac.New(sha512.New, []byte(loginSecret))
		mac.Write([]byte(mxid))
		token := hex.EncodeToString(mac.Sum(nil))
		switch {
		case loginFlows.HasFlow(mautrix.AuthTypeDevtureSharedSecret):
			req.Type = mautrix.AuthTypeDevtureSharedSecret
			req.Token = token
		case loginFlows.HasFlow(mautrix.AuthTypePassword):
			req.Type = mautrix.AuthTypePassword
			req.Password = token
		default:
			return "", fmt.Errorf("no supported auth types for shared secret auth found")
		}
	}
	resp, err := client.Login(ctx, &req)
	if err != nil {
		return "", err
	}
	return resp.AccessToken, nil
}

func (dp *doublePuppetUtil) getLoginSecret(mxid id.UserID) (loginSecret string, hasSecret bool) {
	_, homeserver, _ := mxid.Parse()
	loginSecret, hasSecret = dp.br.Config.Bridge.GetDoublePuppetConfig().SharedSecretMap[homeserver]
	return
}

var (
	ErrMismatchingMXID = errors.New("whoami result does not match custom mxid")
	ErrNoAccessToken   = errors.New("no access token provided")
	ErrNoMXID          = errors.New("no mxid provided")
)

const useConfigASToken = "appservice-config"
const asTokenModePrefix = "as_token:"

func (dp *doublePuppetUtil) CanAutoDoublePuppet(mxid id.UserID) bool {
	_, hasSecret := dp.getLoginSecret(mxid)
	return hasSecret
}

func (dp *doublePuppetUtil) Setup(ctx context.Context, mxid id.UserID, savedAccessToken string, reloginOnFail bool) (intent *appservice.IntentAPI, newAccessToken string, err error) {
	if len(mxid) == 0 {
		err = ErrNoMXID
		return
	}
	loginSecret, hasSecret := dp.getLoginSecret(mxid)
	// Special case appservice: prefix to not login and use it as an as_token directly.
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
	}
	if savedAccessToken == "" || savedAccessToken == useConfigASToken {
		if reloginOnFail && hasSecret {
			savedAccessToken, err = dp.autoLogin(ctx, mxid, loginSecret)
		} else {
			err = ErrNoAccessToken
		}
		if err != nil {
			return
		}
	}
	intent, err = dp.newIntent(ctx, mxid, savedAccessToken)
	if err != nil {
		return
	}
	var resp *mautrix.RespWhoami
	resp, err = intent.Whoami(ctx)
	if err != nil {
		if reloginOnFail && hasSecret && errors.Is(err, mautrix.MUnknownToken) {
			intent.AccessToken, err = dp.autoLogin(ctx, mxid, loginSecret)
			if err == nil {
				newAccessToken = intent.AccessToken
			}
		}
	} else if resp.UserID != mxid {
		err = ErrMismatchingMXID
	} else {
		newAccessToken = savedAccessToken
	}
	return
}
