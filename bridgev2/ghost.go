// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exmime"
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type Ghost struct {
	*database.Ghost
	Bridge *Bridge
	Log    zerolog.Logger
	Intent MatrixAPI
}

func (br *Bridge) loadGhost(ctx context.Context, dbGhost *database.Ghost, queryErr error, id *networkid.UserID) (*Ghost, error) {
	if queryErr != nil {
		return nil, fmt.Errorf("failed to query db: %w", queryErr)
	}
	if dbGhost == nil {
		if id == nil {
			return nil, nil
		}
		dbGhost = &database.Ghost{
			BridgeID: br.ID,
			ID:       *id,
		}
		err := br.DB.Ghost.Insert(ctx, dbGhost)
		if err != nil {
			return nil, fmt.Errorf("failed to insert new ghost: %w", err)
		}
	}
	ghost := &Ghost{
		Ghost:  dbGhost,
		Bridge: br,
		Log:    br.Log.With().Str("ghost_id", string(dbGhost.ID)).Logger(),
		Intent: br.Matrix.GhostIntent(dbGhost.ID),
	}
	br.ghostsByID[ghost.ID] = ghost
	return ghost, nil
}

func (br *Bridge) unlockedGetGhostByID(ctx context.Context, id networkid.UserID, onlyIfExists bool) (*Ghost, error) {
	cached, ok := br.ghostsByID[id]
	if ok {
		return cached, nil
	}
	idPtr := &id
	if onlyIfExists {
		idPtr = nil
	}
	db, err := br.DB.Ghost.GetByID(ctx, id)
	return br.loadGhost(ctx, db, err, idPtr)
}

func (br *Bridge) IsGhostMXID(userID id.UserID) bool {
	_, isGhost := br.Matrix.ParseGhostMXID(userID)
	return isGhost
}

func (br *Bridge) GetGhostByMXID(ctx context.Context, mxid id.UserID) (*Ghost, error) {
	ghostID, ok := br.Matrix.ParseGhostMXID(mxid)
	if !ok {
		return nil, nil
	}
	return br.GetGhostByID(ctx, ghostID)
}

func (br *Bridge) GetGhostByID(ctx context.Context, id networkid.UserID) (*Ghost, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	ghost, err := br.unlockedGetGhostByID(ctx, id, false)
	if err != nil {
		return nil, err
	} else if ghost == nil {
		panic(fmt.Errorf("unlockedGetGhostByID(ctx, %q, false) returned nil", id))
	}
	return ghost, nil
}

func (br *Bridge) GetExistingGhostByID(ctx context.Context, id networkid.UserID) (*Ghost, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.unlockedGetGhostByID(ctx, id, true)
}

type Avatar struct {
	ID     networkid.AvatarID
	Get    func(ctx context.Context) ([]byte, error)
	Remove bool

	// For pre-uploaded avatars, the MXC URI and hash can be provided directly
	MXC  id.ContentURIString
	Hash [32]byte
}

func (a *Avatar) Reupload(ctx context.Context, intent MatrixAPI, currentHash [32]byte, currentMXC id.ContentURIString) (id.ContentURIString, [32]byte, error) {
	if a.MXC != "" || a.Hash != [32]byte{} {
		return a.MXC, a.Hash, nil
	} else if a.Get == nil {
		return "", [32]byte{}, fmt.Errorf("no Get function provided for avatar")
	}
	data, err := a.Get(ctx)
	if err != nil {
		return "", [32]byte{}, err
	}
	hash := sha256.Sum256(data)
	if hash == currentHash && currentMXC != "" {
		return currentMXC, hash, nil
	}
	mime := http.DetectContentType(data)
	fileName := "avatar" + exmime.ExtensionFromMimetype(mime)
	uri, _, err := intent.UploadMedia(ctx, "", data, fileName, mime)
	if err != nil {
		return "", hash, err
	}
	return uri, hash, nil
}

type UserInfo struct {
	Identifiers []string
	Name        *string
	Avatar      *Avatar
	IsBot       *bool

	ExtraUpdates ExtraUpdater[*Ghost]
}

func (ghost *Ghost) UpdateName(ctx context.Context, name string) bool {
	if ghost.Name == name && ghost.NameSet {
		return false
	}
	ghost.Name = name
	ghost.NameSet = false
	err := ghost.Intent.SetDisplayName(ctx, name)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to set display name")
	} else {
		ghost.NameSet = true
	}
	return true
}

func (ghost *Ghost) UpdateAvatar(ctx context.Context, avatar *Avatar) bool {
	if ghost.AvatarID == avatar.ID && ghost.AvatarSet {
		return false
	}
	ghost.AvatarID = avatar.ID
	if !avatar.Remove {
		newMXC, newHash, err := avatar.Reupload(ctx, ghost.Intent, ghost.AvatarHash, ghost.AvatarMXC)
		if err != nil {
			ghost.AvatarSet = false
			zerolog.Ctx(ctx).Err(err).Msg("Failed to reupload avatar")
			return true
		} else if newHash == ghost.AvatarHash && ghost.AvatarSet {
			return true
		}
		ghost.AvatarHash = newHash
		ghost.AvatarMXC = newMXC
	} else {
		ghost.AvatarMXC = ""
	}
	ghost.AvatarSet = false
	if err := ghost.Intent.SetAvatarURL(ctx, ghost.AvatarMXC); err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to set avatar URL")
	} else {
		ghost.AvatarSet = true
	}
	return true
}

func (ghost *Ghost) getExtraProfileMeta() *event.BeeperProfileExtra {
	bridgeName := ghost.Bridge.Network.GetName()
	return &event.BeeperProfileExtra{
		RemoteID:     string(ghost.ID),
		Identifiers:  ghost.Identifiers,
		Service:      bridgeName.BeeperBridgeType,
		Network:      bridgeName.NetworkID,
		IsBridgeBot:  false,
		IsNetworkBot: ghost.IsBot,
	}
}

func (ghost *Ghost) UpdateContactInfo(ctx context.Context, identifiers []string, isBot *bool) bool {
	if identifiers != nil {
		slices.Sort(identifiers)
	}
	if ghost.ContactInfoSet &&
		(identifiers == nil || slices.Equal(identifiers, ghost.Identifiers)) &&
		(isBot == nil || *isBot == ghost.IsBot) {
		return false
	}
	if identifiers != nil {
		ghost.Identifiers = identifiers
	}
	if isBot != nil {
		ghost.IsBot = *isBot
	}
	err := ghost.Intent.SetExtraProfileMeta(ctx, ghost.getExtraProfileMeta())
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to set extra profile metadata")
	} else {
		ghost.ContactInfoSet = true
	}
	return true
}

func (br *Bridge) allowAggressiveUpdateForType(evtType RemoteEventType) bool {
	if !br.Network.GetCapabilities().AggressiveUpdateInfo {
		return false
	}
	switch evtType {
	case RemoteEventUnknown, RemoteEventMessage, RemoteEventEdit, RemoteEventReaction:
		return true
	default:
		return false
	}
}

func (ghost *Ghost) UpdateInfoIfNecessary(ctx context.Context, source *UserLogin, evtType RemoteEventType) {
	if ghost.Name != "" && ghost.NameSet && !ghost.Bridge.allowAggressiveUpdateForType(evtType) {
		return
	}
	info, err := source.Client.GetUserInfo(ctx, ghost)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Str("ghost_id", string(ghost.ID)).Msg("Failed to get info to update ghost")
	} else if info != nil {
		zerolog.Ctx(ctx).Debug().
			Bool("has_name", ghost.Name != "").
			Bool("name_set", ghost.NameSet).
			Msg("Updating ghost info in IfNecessary call")
		ghost.UpdateInfo(ctx, info)
	} else {
		zerolog.Ctx(ctx).Trace().
			Bool("has_name", ghost.Name != "").
			Bool("name_set", ghost.NameSet).
			Msg("No ghost info received in IfNecessary call")
	}
}

func (ghost *Ghost) updateDMPortals(ctx context.Context) {
	if !ghost.Bridge.Config.PrivateChatPortalMeta {
		return
	}
	dmPortals, err := ghost.Bridge.GetDMPortalsWith(ctx, ghost.ID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to get DM portals to update info")
		return
	}
	for _, portal := range dmPortals {
		go portal.lockedUpdateInfoFromGhost(ctx, ghost)
	}
}

func (ghost *Ghost) UpdateInfo(ctx context.Context, info *UserInfo) {
	update := false
	oldName := ghost.Name
	oldAvatar := ghost.AvatarMXC
	if info.Name != nil {
		update = ghost.UpdateName(ctx, *info.Name) || update
	}
	if info.Avatar != nil {
		update = ghost.UpdateAvatar(ctx, info.Avatar) || update
	}
	if info.Identifiers != nil || info.IsBot != nil {
		update = ghost.UpdateContactInfo(ctx, info.Identifiers, info.IsBot) || update
	}
	if info.ExtraUpdates != nil {
		update = info.ExtraUpdates(ctx, ghost) || update
	}
	if oldName != ghost.Name || oldAvatar != ghost.AvatarMXC {
		ghost.updateDMPortals(ctx)
	}
	if update {
		err := ghost.Bridge.DB.Ghost.Update(ctx, ghost.Ghost)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to update ghost in database after updating info")
		}
	}
}
