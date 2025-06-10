// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exsync"

	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
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
	deleteLock      sync.Mutex
	disconnectOnce  sync.Once
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
	} else if userLogin.Client == nil {
		userLogin.Log.Error().Msg("LoadUserLogin didn't fill Client")
		return nil, nil
	}
	userLogin.BridgeState = br.NewBridgeStateQueue(userLogin)
	user.logins[userLogin.ID] = userLogin
	br.userLoginsByID[userLogin.ID] = userLogin
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
	if portal.Receiver != "" {
		ul := br.GetCachedUserLoginByID(portal.Receiver)
		if ul == nil {
			return nil, nil
		}
		return []*UserLogin{ul}, nil
	}
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
	if data.Metadata == nil {
		metaTypes := user.Bridge.Network.GetDBMetaTypes()
		if metaTypes.UserLogin != nil {
			data.Metadata = metaTypes.UserLogin()
		}
	}
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
			ul.Delete(ctx, status.BridgeState{StateEvent: status.StateLoggedOut, Reason: "LOGIN_OVERRIDDEN_ANOTHER_USER"}, DeleteOpts{
				LogoutRemote: false,
				unlocked:     true,
			})
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
		ul.RemoteName = data.RemoteName
		ul.RemoteProfile = ul.RemoteProfile.Merge(data.RemoteProfile)
		if merger, ok := ul.Metadata.(database.MetaMerger); ok {
			merger.CopyFrom(data.Metadata)
		} else {
			ul.Metadata = data.Metadata
		}
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
	noCancelCtx := ul.Log.WithContext(user.Bridge.BackgroundCtx)
	err = params.LoadUserLogin(noCancelCtx, ul)
	if err != nil {
		return nil, err
	} else if ul.Client == nil {
		ul.Log.Error().Msg("LoadUserLogin didn't fill Client in NewLogin")
		return nil, fmt.Errorf("client not filled by LoadUserLogin")
	}
	if doInsert {
		err = user.Bridge.DB.UserLogin.Insert(noCancelCtx, ul.UserLogin)
		if err != nil {
			return nil, err
		}
		user.Bridge.userLoginsByID[ul.ID] = ul
		user.logins[ul.ID] = ul
	} else {
		err = ul.Save(noCancelCtx)
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
	ul.Delete(ctx, status.BridgeState{StateEvent: status.StateLoggedOut}, DeleteOpts{LogoutRemote: true})
}

type DeleteOpts struct {
	LogoutRemote     bool
	DontCleanupRooms bool
	BlockingCleanup  bool
	unlocked         bool
}

func (ul *UserLogin) Delete(ctx context.Context, state status.BridgeState, opts DeleteOpts) {
	cleanupRooms := !opts.DontCleanupRooms && ul.Bridge.Config.CleanupOnLogout.Enabled
	zerolog.Ctx(ctx).Info().Str("user_login_id", string(ul.ID)).
		Bool("logout_remote", opts.LogoutRemote).
		Bool("cleanup_rooms", cleanupRooms).
		Msg("Deleting user login")
	ul.deleteLock.Lock()
	defer ul.deleteLock.Unlock()
	if ul.BridgeState == nil {
		return
	}
	if opts.LogoutRemote {
		ul.Client.LogoutRemote(ctx)
	} else {
		// we probably shouldn't delete the login if disconnect isn't finished
		ul.Disconnect()
	}
	var portals []*database.UserPortal
	var err error
	if cleanupRooms {
		portals, err = ul.Bridge.DB.UserPortal.GetAllForLogin(ctx, ul.UserLogin)
		if err != nil {
			ul.Log.Err(err).Msg("Failed to get user portals")
		}
	}
	err = ul.Bridge.DB.UserLogin.Delete(ctx, ul.ID)
	if err != nil {
		ul.Log.Err(err).Msg("Failed to delete user login")
	}
	if !opts.unlocked {
		ul.Bridge.cacheLock.Lock()
	}
	delete(ul.User.logins, ul.ID)
	delete(ul.Bridge.userLoginsByID, ul.ID)
	if !opts.unlocked {
		ul.Bridge.cacheLock.Unlock()
	}
	backgroundCtx := zerolog.Ctx(ctx).WithContext(ul.Bridge.BackgroundCtx)
	if !opts.BlockingCleanup {
		go ul.deleteSpace(backgroundCtx)
	} else {
		ul.deleteSpace(backgroundCtx)
	}
	if portals != nil {
		if !opts.BlockingCleanup {
			go ul.kickUserFromPortals(backgroundCtx, portals, state.StateEvent == status.StateBadCredentials, false)
		} else {
			ul.kickUserFromPortals(backgroundCtx, portals, state.StateEvent == status.StateBadCredentials, false)
		}
	}
	if state.StateEvent != "" {
		ul.BridgeState.Send(state)
	}
	ul.BridgeState.Destroy()
	ul.BridgeState = nil
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

// KickUserFromPortalsForBadCredentials can be called to kick the user from portals without deleting the entire UserLogin object.
func (ul *UserLogin) KickUserFromPortalsForBadCredentials(ctx context.Context) {
	log := zerolog.Ctx(ctx)
	portals, err := ul.Bridge.DB.UserPortal.GetAllForLogin(ctx, ul.UserLogin)
	if err != nil {
		log.Err(err).Msg("Failed to get user portals")
	}
	ul.kickUserFromPortals(ctx, portals, true, true)
}

func DeleteManyPortals(ctx context.Context, portals []*Portal, errorCallback func(portal *Portal, delete bool, err error)) {
	// TODO is there a more sensible place/name for this function?
	if len(portals) == 0 {
		return
	}
	getDepth := func(portal *Portal) int {
		depth := 0
		for portal.Parent != nil {
			depth++
			portal = portal.Parent
		}
		return depth
	}
	// Sort portals so parents are last (to avoid errors caused by deleting parent portals before children)
	slices.SortFunc(portals, func(a, b *Portal) int {
		return cmp.Compare(getDepth(b), getDepth(a))
	})
	for _, portal := range portals {
		err := portal.Delete(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Stringer("portal_mxid", portal.MXID).
				Object("portal_key", portal.PortalKey).
				Msg("Failed to delete portal row from database")
			if errorCallback != nil {
				errorCallback(portal, false, err)
			}
			continue
		}
		if portal.MXID != "" {
			err = portal.Bridge.Bot.DeleteRoom(ctx, portal.MXID, false)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).
					Stringer("portal_mxid", portal.MXID).
					Msg("Failed to clean up portal room")
				if errorCallback != nil {
					errorCallback(portal, true, err)
				}
			}
		}
	}
}

func (ul *UserLogin) kickUserFromPortals(ctx context.Context, portals []*database.UserPortal, badCredentials, deleteRow bool) {
	var portalsToDelete []*Portal
	for _, up := range portals {
		portalToDelete, err := ul.kickUserFromPortal(ctx, up, badCredentials, deleteRow)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Object("portal_key", up.Portal).
				Stringer("user_mxid", up.UserMXID).
				Msg("Failed to apply logout action")
		} else if portalToDelete != nil {
			portalsToDelete = append(portalsToDelete, portalToDelete)
		}
	}
	DeleteManyPortals(ctx, portalsToDelete, nil)
}

func (ul *UserLogin) kickUserFromPortal(ctx context.Context, up *database.UserPortal, badCredentials, deleteRow bool) (*Portal, error) {
	portal, action, reason, err := ul.getLogoutAction(ctx, up, badCredentials)
	if err != nil {
		return nil, err
	} else if portal == nil {
		return nil, nil
	}
	zerolog.Ctx(ctx).Debug().
		Str("login_id", string(ul.ID)).
		Stringer("user_mxid", ul.UserMXID).
		Str("logout_action", string(action)).
		Str("action_reason", reason).
		Object("portal_key", portal.PortalKey).
		Stringer("portal_mxid", portal.MXID).
		Msg("Calculated portal action for logout processing")
	switch action {
	case bridgeconfig.CleanupActionNull, bridgeconfig.CleanupActionNothing:
		// do nothing
	case bridgeconfig.CleanupActionKick:
		_, err = ul.Bridge.Bot.SendState(ctx, portal.MXID, event.StateMember, ul.UserMXID.String(), &event.Content{
			Parsed: &event.MemberEventContent{
				Membership: event.MembershipLeave,
				Reason:     "Logged out of bridge",
			},
		}, time.Time{})
		if err != nil {
			return nil, fmt.Errorf("failed to kick user from portal: %w", err)
		}
		zerolog.Ctx(ctx).Debug().
			Str("login_id", string(ul.ID)).
			Stringer("user_mxid", ul.UserMXID).
			Stringer("portal_mxid", portal.MXID).
			Msg("Kicked user from portal")
		if deleteRow {
			err = ul.Bridge.DB.UserPortal.Delete(ctx, up)
			if err != nil {
				zerolog.Ctx(ctx).Warn().
					Str("login_id", string(ul.ID)).
					Stringer("user_mxid", ul.UserMXID).
					Stringer("portal_mxid", portal.MXID).
					Msg("Failed to delete user portal row")
			}
		}
	case bridgeconfig.CleanupActionDelete, bridgeconfig.CleanupActionUnbridge:
		// return portal instead of deleting here to allow sorting by depth
		return portal, nil
	}
	return nil, nil
}

func (ul *UserLogin) getLogoutAction(ctx context.Context, up *database.UserPortal, badCredentials bool) (*Portal, bridgeconfig.CleanupAction, string, error) {
	portal, err := ul.Bridge.GetExistingPortalByKey(ctx, up.Portal)
	if err != nil {
		return nil, bridgeconfig.CleanupActionNull, "", fmt.Errorf("failed to get full portal: %w", err)
	} else if portal == nil || portal.MXID == "" {
		return nil, bridgeconfig.CleanupActionNull, "portal not found", nil
	}
	actionsSet := ul.Bridge.Config.CleanupOnLogout.Manual
	if badCredentials {
		actionsSet = ul.Bridge.Config.CleanupOnLogout.BadCredentials
	}
	if portal.Receiver != "" {
		return portal, actionsSet.Private, "portal has receiver", nil
	}
	otherUPs, err := ul.Bridge.DB.UserPortal.GetAllInPortal(ctx, portal.PortalKey)
	if err != nil {
		return portal, bridgeconfig.CleanupActionNull, "", fmt.Errorf("failed to get other logins in portal: %w", err)
	}
	hasOtherUsers := false
	for _, otherUP := range otherUPs {
		if otherUP.LoginID == ul.ID {
			continue
		}
		if otherUP.UserMXID == ul.UserMXID {
			otherUL := ul.Bridge.GetCachedUserLoginByID(otherUP.LoginID)
			if otherUL != nil && otherUL.Client.IsLoggedIn() {
				return portal, bridgeconfig.CleanupActionNull, "user has another login in portal", nil
			}
		} else {
			hasOtherUsers = true
		}
	}
	if portal.RelayLoginID != "" {
		return portal, actionsSet.Relayed, "portal has relay login", nil
	} else if hasOtherUsers {
		return portal, actionsSet.SharedHasUsers, "portal has logins of other users", nil
	}
	return portal, actionsSet.SharedNoUsers, "portal doesn't have logins of other users", nil
}

func (ul *UserLogin) MarkAsPreferredIn(ctx context.Context, portal *Portal) error {
	return ul.Bridge.DB.UserPortal.MarkAsPreferred(ctx, ul.UserLogin, portal.PortalKey)
}

var _ status.BridgeStateFiller = (*UserLogin)(nil)

func (ul *UserLogin) FillBridgeState(state status.BridgeState) status.BridgeState {
	state.UserID = ul.UserMXID
	state.RemoteID = string(ul.ID)
	state.RemoteName = ul.RemoteName
	state.RemoteProfile = &ul.RemoteProfile
	filler, ok := ul.Client.(status.BridgeStateFiller)
	if ok {
		return filler.FillBridgeState(state)
	}
	return state
}

func (ul *UserLogin) Disconnect() {
	ul.DisconnectWithTimeout(0)
}

func (ul *UserLogin) DisconnectWithTimeout(timeout time.Duration) {
	ul.disconnectOnce.Do(func() {
		ul.disconnectInternal(timeout)
	})
}

func (ul *UserLogin) disconnectInternal(timeout time.Duration) {
	disconnected := make(chan struct{})
	go func() {
		ul.Client.Disconnect()
		close(disconnected)
	}()

	var timeoutC <-chan time.Time
	if timeout > 0 {
		timeoutC = time.After(timeout)
	}
	for {
		select {
		case <-disconnected:
			return
		case <-time.After(2 * time.Second):
			ul.Log.Warn().Msg("Client disconnection taking long")
		case <-timeoutC:
			ul.Log.Error().Msg("Client disconnection timed out")
			return
		}
	}
}
