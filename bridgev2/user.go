// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type User struct {
	*database.User
	Bridge *Bridge
	Log    zerolog.Logger

	CommandState atomic.Pointer[CommandState]

	logins map[networkid.UserLoginID]*UserLogin
}

func (br *Bridge) loadUser(ctx context.Context, dbUser *database.User, queryErr error, userID *id.UserID) (*User, error) {
	if queryErr != nil {
		return nil, fmt.Errorf("failed to query db: %w", queryErr)
	}
	if dbUser == nil {
		if userID == nil {
			return nil, nil
		}
		dbUser = &database.User{
			BridgeID: br.ID,
			MXID:     *userID,
		}
		err := br.DB.User.Insert(ctx, dbUser)
		if err != nil {
			return nil, fmt.Errorf("failed to insert new user: %w", err)
		}
	}
	user := &User{
		User:   dbUser,
		Bridge: br,
		Log:    br.Log.With().Stringer("user_mxid", dbUser.MXID).Logger(),
		logins: make(map[networkid.UserLoginID]*UserLogin),
	}
	br.usersByMXID[user.MXID] = user
	err := br.unlockedLoadUserLoginsByMXID(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to load user logins: %w", err)
	}
	return user, nil
}

func (br *Bridge) unlockedGetUserByMXID(ctx context.Context, userID id.UserID, onlyIfExists bool) (*User, error) {
	cached, ok := br.usersByMXID[userID]
	if ok {
		return cached, nil
	}
	idPtr := &userID
	if onlyIfExists {
		idPtr = nil
	}
	db, err := br.DB.User.GetByMXID(ctx, userID)
	return br.loadUser(ctx, db, err, idPtr)
}

func (br *Bridge) GetUserByMXID(ctx context.Context, userID id.UserID) (*User, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.unlockedGetUserByMXID(ctx, userID, false)
}

func (br *Bridge) GetExistingUserByMXID(ctx context.Context, userID id.UserID) (*User, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.unlockedGetUserByMXID(ctx, userID, true)
}
