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
	MXID   id.UserID
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
	mxid := br.Matrix.FormatGhostMXID(dbGhost.ID)
	ghost := &Ghost{
		Ghost:  dbGhost,
		Bridge: br,
		Log:    br.Log.With().Str("ghost_id", string(dbGhost.ID)).Logger(),
		Intent: br.Matrix.GhostIntent(mxid),
		MXID:   mxid,
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
	return br.unlockedGetGhostByID(ctx, id, false)
}

func (ghost *Ghost) IntentFor(portal *Portal) MatrixAPI {
	// TODO use user double puppet intent if appropriate
	return ghost.Intent
}

type Avatar struct {
	ID     networkid.AvatarID
	Get    func(ctx context.Context) ([]byte, error)
	Remove bool
}

func (a *Avatar) Reupload(ctx context.Context, intent MatrixAPI, currentHash [32]byte) (id.ContentURIString, [32]byte, error) {
	data, err := a.Get(ctx)
	if err != nil {
		return "", [32]byte{}, err
	}
	hash := sha256.Sum256(data)
	if hash == currentHash {
		return "", hash, nil
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
		newMXC, newHash, err := avatar.Reupload(ctx, ghost.Intent, ghost.AvatarHash)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to reupload avatar")
			return true
		} else if newHash == ghost.AvatarHash {
			return true
		}
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

func (ghost *Ghost) UpdateContactInfo(ctx context.Context, identifiers []string, isBot *bool) bool {
	if identifiers != nil {
		slices.Sort(identifiers)
	}
	if ghost.Metadata.ContactInfoSet &&
		(identifiers == nil || slices.Equal(identifiers, ghost.Metadata.Identifiers)) &&
		(isBot == nil || *isBot == ghost.Metadata.IsBot) {
		return false
	}
	if identifiers != nil {
		ghost.Metadata.Identifiers = identifiers
	}
	if isBot != nil {
		ghost.Metadata.IsBot = *isBot
	}
	bridgeName := ghost.Bridge.Network.GetName()
	meta := &event.BeeperProfileExtra{
		RemoteID:     string(ghost.ID),
		Identifiers:  ghost.Metadata.Identifiers,
		Service:      bridgeName.BeeperBridgeType,
		Network:      bridgeName.NetworkID,
		IsBridgeBot:  false,
		IsNetworkBot: ghost.Metadata.IsBot,
	}
	err := ghost.Intent.SetExtraProfileMeta(ctx, meta)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to set extra profile metadata")
	} else {
		ghost.Metadata.ContactInfoSet = true
	}
	return true
}

func (ghost *Ghost) UpdateInfoIfNecessary(ctx context.Context, source *UserLogin) {
	if ghost.Name != "" && ghost.NameSet {
		return
	}
	info, err := source.Client.GetUserInfo(ctx, ghost)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Failed to get info to update ghost")
	}
	ghost.UpdateInfo(ctx, info)
}

func (ghost *Ghost) UpdateInfo(ctx context.Context, info *UserInfo) {
	update := false
	if info.Name != nil {
		update = ghost.UpdateName(ctx, *info.Name) || update
	}
	if info.Avatar != nil {
		update = ghost.UpdateAvatar(ctx, info.Avatar) || update
	}
	if info.Identifiers != nil || info.IsBot != nil {
		update = ghost.UpdateContactInfo(ctx, info.Identifiers, info.IsBot) || update
	}
	if update {
		err := ghost.Bridge.DB.Ghost.Update(ctx, ghost.Ghost)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to update ghost in database after updating info")
		}
	}
}
