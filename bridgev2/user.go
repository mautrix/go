// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type User struct {
	*database.User
	Bridge *Bridge
	Log    zerolog.Logger

	CommandState unsafe.Pointer
	Permissions  bridgeconfig.Permissions

	doublePuppetIntent      MatrixAPI
	doublePuppetInitialized bool
	doublePuppetLock        sync.Mutex

	managementCreateLock sync.Mutex

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
		User:        dbUser,
		Bridge:      br,
		Log:         br.Log.With().Stringer("user_mxid", dbUser.MXID).Logger(),
		logins:      make(map[networkid.UserLoginID]*UserLogin),
		Permissions: br.Config.Permissions.Get(dbUser.MXID),
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

func (user *User) LogoutDoublePuppet(ctx context.Context) {
	user.doublePuppetLock.Lock()
	defer user.doublePuppetLock.Unlock()
	user.AccessToken = ""
	err := user.Save(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to save removed access token")
	}
	user.doublePuppetIntent = nil
	user.doublePuppetInitialized = false
}

func (user *User) LoginDoublePuppet(ctx context.Context, token string) error {
	if token == "" {
		return fmt.Errorf("no token provided")
	}
	user.doublePuppetLock.Lock()
	defer user.doublePuppetLock.Unlock()
	intent, newToken, err := user.Bridge.Matrix.NewUserIntent(ctx, user.MXID, token)
	if err != nil {
		return err
	}
	user.AccessToken = newToken
	user.doublePuppetIntent = intent
	user.doublePuppetInitialized = true
	err = user.Save(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to save new access token")
	}
	if newToken != token {
		return fmt.Errorf("logging in manually is not supported when automatic double puppeting is enabled")
	}
	return nil
}

func (user *User) DoublePuppet(ctx context.Context) MatrixAPI {
	user.doublePuppetLock.Lock()
	defer user.doublePuppetLock.Unlock()
	if user.doublePuppetInitialized {
		return user.doublePuppetIntent
	}
	user.doublePuppetInitialized = true
	log := user.Log.With().Str("action", "setup double puppet").Logger()
	ctx = log.WithContext(ctx)
	intent, newToken, err := user.Bridge.Matrix.NewUserIntent(ctx, user.MXID, user.AccessToken)
	if err != nil {
		log.Err(err).Msg("Failed to create new user intent")
		return nil
	}
	user.doublePuppetIntent = intent
	if newToken != user.AccessToken {
		user.AccessToken = newToken
		err = user.Save(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to save new access token")
		}
	}
	return intent
}

func (user *User) GetUserLoginIDs() []networkid.UserLoginID {
	user.Bridge.cacheLock.Lock()
	defer user.Bridge.cacheLock.Unlock()
	return maps.Keys(user.logins)
}

// Deprecated: renamed to GetUserLogins
func (user *User) GetCachedUserLogins() []*UserLogin {
	return user.GetUserLogins()
}

func (user *User) GetUserLogins() []*UserLogin {
	user.Bridge.cacheLock.Lock()
	defer user.Bridge.cacheLock.Unlock()
	return maps.Values(user.logins)
}

func (user *User) HasTooManyLogins() bool {
	return user.Permissions.MaxLogins > 0 && len(user.GetUserLoginIDs()) >= user.Permissions.MaxLogins
}

func (user *User) GetFormattedUserLogins() string {
	user.Bridge.cacheLock.Lock()
	logins := make([]string, len(user.logins))
	for key, val := range user.logins {
		logins = append(logins, fmt.Sprintf("* `%s` (%s) - `%s`", key, val.RemoteName, val.BridgeState.GetPrev().StateEvent))
	}
	user.Bridge.cacheLock.Unlock()
	return strings.Join(logins, "\n")
}

func (user *User) GetDefaultLogin() *UserLogin {
	user.Bridge.cacheLock.Lock()
	defer user.Bridge.cacheLock.Unlock()
	if len(user.logins) == 0 {
		return nil
	}
	loginKeys := maps.Keys(user.logins)
	slices.Sort(loginKeys)
	return user.logins[loginKeys[0]]
}

func (user *User) GetManagementRoom(ctx context.Context) (id.RoomID, error) {
	user.managementCreateLock.Lock()
	defer user.managementCreateLock.Unlock()
	if user.ManagementRoom != "" {
		return user.ManagementRoom, nil
	}
	netName := user.Bridge.Network.GetName()
	var err error
	autoJoin := user.Bridge.Matrix.GetCapabilities().AutoJoinInvites
	doublePuppet := user.DoublePuppet(ctx)
	req := &mautrix.ReqCreateRoom{
		Visibility: "private",
		Name:       netName.DisplayName,
		Topic:      fmt.Sprintf("%s bridge management room", netName.DisplayName),
		InitialState: []*event.Event{{
			Type: event.StateRoomAvatar,
			Content: event.Content{
				Parsed: &event.RoomAvatarEventContent{
					URL: netName.NetworkIcon,
				},
			},
		}},
		PowerLevelOverride: &event.PowerLevelsEventContent{
			Users: map[id.UserID]int{
				user.Bridge.Bot.GetMXID(): 9001,
				user.MXID:                 50,
			},
		},
		RoomVersion: id.RoomV11,
		Invite:      []id.UserID{user.MXID},
		IsDirect:    true,
	}
	if autoJoin {
		req.BeeperInitialMembers = []id.UserID{user.MXID}
		// TODO remove this after initial_members is supported in hungryserv
		req.BeeperAutoJoinInvites = true
	}
	user.ManagementRoom, err = user.Bridge.Bot.CreateRoom(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to create management room: %w", err)
	}
	if !autoJoin && doublePuppet != nil {
		err = doublePuppet.EnsureJoined(ctx, user.ManagementRoom)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to auto-join created management room with double puppet")
		}
	}
	err = user.Save(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to save management room ID: %w", err)
	}
	return user.ManagementRoom, nil
}

func (user *User) Save(ctx context.Context) error {
	return user.Bridge.DB.User.Update(ctx, user.User)
}

func (br *Bridge) TrackAnalytics(userID id.UserID, event string, props map[string]any) {
	analyticSender, ok := br.Matrix.(MatrixConnectorWithAnalytics)
	if ok {
		analyticSender.TrackAnalytics(userID, event, props)
	}
}

func (user *User) TrackAnalytics(event string, props map[string]any) {
	user.Bridge.TrackAnalytics(user.MXID, event, props)
}

func (ul *UserLogin) TrackAnalytics(event string, props map[string]any) {
	// TODO include user login ID?
	ul.Bridge.TrackAnalytics(ul.UserMXID, event, props)
}
