// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

type UserLogin struct {
	*database.UserLogin
	Bridge *Bridge
	User   *User
	Log    zerolog.Logger

	Client NetworkAPI
}

func (br *Bridge) loadUserLogin(ctx context.Context, user *User, dbUserLogin *database.UserLogin) (*UserLogin, error) {
	if user == nil {
		var err error
		user, err = br.unlockedGetUserByMXID(ctx, dbUserLogin.UserMXID, true)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
	}
	userLogin := &UserLogin{
		UserLogin: dbUserLogin,
		Bridge:    br,
		User:      user,
		Log:       user.Log.With().Str("login_id", string(dbUserLogin.ID)).Logger(),
	}
	err := br.Network.PrepareLogin(ctx, userLogin)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare: %w", err)
	}
	user.logins[userLogin.ID] = userLogin
	br.userLoginsByID[userLogin.ID] = userLogin
	return userLogin, nil
}

func (br *Bridge) loadManyUserLogins(ctx context.Context, user *User, logins []*database.UserLogin) ([]*UserLogin, error) {
	output := make([]*UserLogin, len(logins))
	for i, dbLogin := range logins {
		if cached, ok := br.userLoginsByID[dbLogin.ID]; ok {
			output[i] = cached
		} else {
			loaded, err := br.loadUserLogin(ctx, user, dbLogin)
			if err != nil {
				return nil, fmt.Errorf("failed to load user login: %w", err)
			}
			output[i] = loaded
		}
	}
	return output, nil
}

func (br *Bridge) unlockedLoadUserLoginsByMXID(ctx context.Context, user *User) error {
	logins, err := br.DB.UserLogin.GetAllForUser(ctx, user.MXID)
	if err != nil {
		return err
	}
	_, err = br.loadManyUserLogins(ctx, user, logins)
	return err
}

func (br *Bridge) GetAllUserLogins(ctx context.Context) ([]*UserLogin, error) {
	logins, err := br.DB.UserLogin.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.loadManyUserLogins(ctx, nil, logins)
}

func (br *Bridge) GetUserLoginsInPortal(ctx context.Context, portalID networkid.PortalID) ([]*UserLogin, error) {
	logins, err := br.DB.UserLogin.GetAllInPortal(ctx, portalID)
	if err != nil {
		return nil, err
	}
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.loadManyUserLogins(ctx, nil, logins)
}

func (br *Bridge) GetCachedUserLoginByID(id networkid.UserLoginID) *UserLogin {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.userLoginsByID[id]
}

func (user *User) NewLogin(ctx context.Context, data *database.UserLogin, client NetworkAPI) (*UserLogin, error) {
	data.BridgeID = user.BridgeID
	data.UserMXID = user.MXID
	ul := &UserLogin{
		UserLogin: data,
		Bridge:    user.Bridge,
		User:      user,
		Log:       user.Log.With().Str("login_id", string(data.ID)).Logger(),
		Client:    client,
	}
	err := user.Bridge.DB.UserLogin.Insert(ctx, ul.UserLogin)
	if err != nil {
		return nil, err
	}
	user.Bridge.cacheLock.Lock()
	defer user.Bridge.cacheLock.Unlock()
	user.Bridge.userLoginsByID[ul.ID] = ul
	user.logins[ul.ID] = ul
	return ul, nil
}
