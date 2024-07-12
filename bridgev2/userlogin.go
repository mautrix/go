// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exsync"

	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type UserLogin struct {
	*database.UserLogin
	Bridge *Bridge
	User   *User
	Log    zerolog.Logger

	Client      NetworkAPI
	BridgeState *BridgeStateQueue

	inPortalCache *exsync.Set[networkid.PortalKey]

	spaceCreateLock sync.Mutex
}

func (br *Bridge) loadUserLogin(ctx context.Context, user *User, dbUserLogin *database.UserLogin) (*UserLogin, error) {
	if dbUserLogin == nil {
		return nil, nil
	}
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

		inPortalCache: exsync.NewSet[networkid.PortalKey](),
	}
	err := br.Network.LoadUserLogin(ctx, userLogin)
	if err != nil {
		userLogin.Log.Err(err).Msg("Failed to load user login")
		return nil, nil
	}
	user.logins[userLogin.ID] = userLogin
	br.userLoginsByID[userLogin.ID] = userLogin
	userLogin.BridgeState = br.NewBridgeStateQueue(userLogin)
	return userLogin, nil
}

func (br *Bridge) loadManyUserLogins(ctx context.Context, user *User, logins []*database.UserLogin) ([]*UserLogin, error) {
	output := make([]*UserLogin, 0, len(logins))
	for _, dbLogin := range logins {
		if cached, ok := br.userLoginsByID[dbLogin.ID]; ok {
			output = append(output, cached)
		} else {
			loaded, err := br.loadUserLogin(ctx, user, dbLogin)
			if err != nil {
				return nil, err
			} else if loaded != nil {
				output = append(output, loaded)
			}
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

func (br *Bridge) GetUserLoginsInPortal(ctx context.Context, portal networkid.PortalKey) ([]*UserLogin, error) {
	logins, err := br.DB.UserLogin.GetAllInPortal(ctx, portal)
	if err != nil {
		return nil, err
	}
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.loadManyUserLogins(ctx, nil, logins)
}

func (br *Bridge) GetExistingUserLoginByID(ctx context.Context, id networkid.UserLoginID) (*UserLogin, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.unlockedGetExistingUserLoginByID(ctx, id)
}

func (br *Bridge) unlockedGetExistingUserLoginByID(ctx context.Context, id networkid.UserLoginID) (*UserLogin, error) {
	cached, ok := br.userLoginsByID[id]
	if ok {
		return cached, nil
	}
	login, err := br.DB.UserLogin.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return br.loadUserLogin(ctx, nil, login)
}

func (br *Bridge) GetCachedUserLoginByID(id networkid.UserLoginID) *UserLogin {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.userLoginsByID[id]
}

func (br *Bridge) GetCurrentBridgeStates() (states []status.BridgeState) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	if len(br.userLoginsByID) == 0 {
		return []status.BridgeState{{
			StateEvent: status.StateUnconfigured,
		}}
	}
	states = make([]status.BridgeState, len(br.userLoginsByID))
	i := 0
	for _, login := range br.userLoginsByID {
		states[i] = login.BridgeState.GetPrev()
		i++
	}
	return
}

type NewLoginParams struct {
	LoadUserLogin     func(context.Context, *UserLogin) error
	DeleteOnConflict  bool
	DontReuseExisting bool
}

// NewLogin creates a UserLogin object for this user with the given parameters.
//
// If a login already exists with the same ID, it is reused after updating the remote name
// and metadata from the provided data, unless DontReuseExisting is set in params.
//
// If the existing login belongs to another user, this returns an error,
// unless DeleteOnConflict is set in the params, in which case the existing login is deleted.
//
// This will automatically call LoadUserLogin after creating the UserLogin object.
// The load method defaults to the network connector's LoadUserLogin method, but it can be overridden in params.
func (user *User) NewLogin(ctx context.Context, data *database.UserLogin, params *NewLoginParams) (*UserLogin, error) {
	user.Bridge.cacheLock.Lock()
	defer user.Bridge.cacheLock.Unlock()
	data.BridgeID = user.BridgeID
	data.UserMXID = user.MXID
	if params == nil {
		params = &NewLoginParams{}
	}
	if params.LoadUserLogin == nil {
		params.LoadUserLogin = user.Bridge.Network.LoadUserLogin
	}
	ul, err := user.Bridge.unlockedGetExistingUserLoginByID(ctx, data.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check if login already exists: %w", err)
	}
	var doInsert bool
	if ul != nil && ul.UserMXID != user.MXID {
		if params.DeleteOnConflict {
			ul.delete(ctx, status.BridgeState{StateEvent: status.StateLoggedOut, Error: "overridden-by-another-user"}, false, true)
			ul = nil
		} else {
			return nil, fmt.Errorf("%s is already logged in with that account", ul.UserMXID)
		}
	}
	if ul != nil {
		if params.DontReuseExisting {
			return nil, fmt.Errorf("login already exists")
		}
		doInsert = false
		ul.Metadata.RemoteName = data.Metadata.RemoteName
		maps.Copy(ul.Metadata.Extra, data.Metadata.Extra)
	} else {
		doInsert = true
		ul = &UserLogin{
			UserLogin: data,
			Bridge:    user.Bridge,
			User:      user,
			Log:       user.Log.With().Str("login_id", string(data.ID)).Logger(),
		}
		ul.BridgeState = user.Bridge.NewBridgeStateQueue(ul)
	}
	err = params.LoadUserLogin(ul.Log.WithContext(context.Background()), ul)
	if err != nil {
		return nil, err
	}
	if doInsert {
		err = user.Bridge.DB.UserLogin.Insert(ctx, ul.UserLogin)
		if err != nil {
			return nil, err
		}
		user.Bridge.userLoginsByID[ul.ID] = ul
		user.logins[ul.ID] = ul
	} else {
		err = ul.Save(ctx)
		if err != nil {
			return nil, err
		}
	}
	return ul, nil
}

func (ul *UserLogin) Save(ctx context.Context) error {
	return ul.Bridge.DB.UserLogin.Update(ctx, ul.UserLogin)
}

func (ul *UserLogin) Logout(ctx context.Context) {
	ul.Delete(ctx, status.BridgeState{StateEvent: status.StateLoggedOut}, true)
}

func (ul *UserLogin) Delete(ctx context.Context, state status.BridgeState, logoutRemote bool) {
	ul.delete(ctx, state, logoutRemote, false)
}

func (ul *UserLogin) delete(ctx context.Context, state status.BridgeState, logoutRemote, unlocked bool) {
	if logoutRemote {
		ul.Client.LogoutRemote(ctx)
	} else {
		ul.Disconnect(nil)
	}
	portals, err := ul.Bridge.DB.UserPortal.GetAllForLogin(ctx, ul.UserLogin)
	if err != nil {
		ul.Log.Err(err).Msg("Failed to get user portals")
	}
	err = ul.Bridge.DB.UserLogin.Delete(ctx, ul.ID)
	if err != nil {
		ul.Log.Err(err).Msg("Failed to delete user login")
	}
	if !unlocked {
		ul.Bridge.cacheLock.Lock()
	}
	delete(ul.User.logins, ul.ID)
	delete(ul.Bridge.userLoginsByID, ul.ID)
	if !unlocked {
		ul.Bridge.cacheLock.Unlock()
	}
	go ul.deleteSpace(ctx)
	go ul.kickUserFromPortals(ctx, portals)
	if state.StateEvent != "" {
		ul.BridgeState.Send(state)
	}
	ul.BridgeState.Destroy()
}

func (ul *UserLogin) deleteSpace(ctx context.Context) {
	if ul.SpaceRoom == "" {
		return
	}
	err := ul.Bridge.Bot.DeleteRoom(ctx, ul.SpaceRoom, false)
	if err != nil {
		ul.Log.Err(err).Msg("Failed to delete space room")
	}
}

func (ul *UserLogin) kickUserFromPortals(ctx context.Context, portals []*database.UserPortal) {
	// TODO kick user out of rooms
}

func (ul *UserLogin) MarkAsPreferredIn(ctx context.Context, portal *Portal) error {
	return ul.Bridge.DB.UserPortal.MarkAsPreferred(ctx, ul.UserLogin, portal.PortalKey)
}

var _ status.BridgeStateFiller = (*UserLogin)(nil)

func (ul *UserLogin) GetMXID() id.UserID {
	return ul.UserMXID
}

func (ul *UserLogin) GetRemoteID() string {
	return string(ul.ID)
}

func (ul *UserLogin) GetRemoteName() string {
	return ul.Metadata.RemoteName
}

func (ul *UserLogin) Disconnect(done func()) {
	if done != nil {
		defer done()
	}
	client := ul.Client
	if client != nil {
		ul.Client = nil
		disconnected := make(chan struct{})
		go func() {
			client.Disconnect()
			close(disconnected)
		}()
		select {
		case <-disconnected:
		case <-time.After(5 * time.Second):
			ul.Log.Warn().Msg("Client disconnection timed out")
		}
	}
}
