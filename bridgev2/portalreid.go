// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
)

type ReIDResult int

const (
	ReIDResultError ReIDResult = iota
	ReIDResultNoOp
	ReIDResultSourceDeleted
	ReIDResultSourceReIDd
	ReIDResultTargetDeletedAndSourceReIDd
	ReIDResultSourceTombstonedIntoTarget
)

func (br *Bridge) ReIDPortal(ctx context.Context, source, target networkid.PortalKey) (ReIDResult, *Portal, error) {
	if source == target {
		return ReIDResultError, nil, fmt.Errorf("illegal re-ID call: source and target are the same")
	}
	log := zerolog.Ctx(ctx)
	log.Debug().Msg("Re-ID'ing portal")
	defer func() {
		log.Debug().Msg("Finished handling portal re-ID")
	}()
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	sourcePortal, err := br.UnlockedGetPortalByKey(ctx, source, true)
	if err != nil {
		return ReIDResultError, nil, fmt.Errorf("failed to get source portal: %w", err)
	} else if sourcePortal == nil {
		log.Debug().Msg("Source portal not found, re-ID is no-op")
		return ReIDResultNoOp, nil, nil
	}
	sourcePortal.roomCreateLock.Lock()
	defer sourcePortal.roomCreateLock.Unlock()
	if sourcePortal.MXID == "" {
		log.Info().Msg("Source portal doesn't have Matrix room, deleting row")
		err = sourcePortal.unlockedDelete(ctx)
		if err != nil {
			return ReIDResultError, nil, fmt.Errorf("failed to delete source portal: %w", err)
		}
		return ReIDResultSourceDeleted, nil, nil
	}
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Stringer("source_portal_mxid", sourcePortal.MXID)
	})
	targetPortal, err := br.UnlockedGetPortalByKey(ctx, target, true)
	if err != nil {
		return ReIDResultError, nil, fmt.Errorf("failed to get target portal: %w", err)
	}
	if targetPortal == nil {
		log.Info().Msg("Target portal doesn't exist, re-ID'ing source portal")
		err = sourcePortal.unlockedReID(ctx, target)
		if err != nil {
			return ReIDResultError, nil, fmt.Errorf("failed to re-ID source portal: %w", err)
		}
		return ReIDResultSourceReIDd, sourcePortal, nil
	}
	targetPortal.roomCreateLock.Lock()
	defer targetPortal.roomCreateLock.Unlock()
	if targetPortal.MXID == "" {
		log.Info().Msg("Target portal row exists, but doesn't have a Matrix room. Deleting target portal row and re-ID'ing source portal")
		err = targetPortal.unlockedDelete(ctx)
		if err != nil {
			return ReIDResultError, nil, fmt.Errorf("failed to delete target portal: %w", err)
		}
		err = sourcePortal.unlockedReID(ctx, target)
		if err != nil {
			return ReIDResultError, nil, fmt.Errorf("failed to re-ID source portal after deleting target: %w", err)
		}
		return ReIDResultTargetDeletedAndSourceReIDd, sourcePortal, nil
	} else {
		log.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Stringer("target_portal_mxid", targetPortal.MXID)
		})
		log.Info().Msg("Both target and source portals have Matrix rooms, tombstoning source portal")
		err = sourcePortal.unlockedDelete(ctx)
		if err != nil {
			return ReIDResultError, nil, fmt.Errorf("failed to delete source portal row: %w", err)
		}
		go func() {
			_, err := br.Bot.SendState(ctx, sourcePortal.MXID, event.StateTombstone, "", &event.Content{
				Parsed: &event.TombstoneEventContent{
					Body:            fmt.Sprintf("This room has been merged"),
					ReplacementRoom: targetPortal.MXID,
				},
			}, time.Now())
			if err != nil {
				log.Err(err).Msg("Failed to send tombstone to source portal room")
			}
			err = br.Bot.DeleteRoom(ctx, sourcePortal.MXID, err == nil)
			if err != nil {
				log.Err(err).Msg("Failed to delete source portal room")
			}
		}()
		return ReIDResultSourceTombstonedIntoTarget, targetPortal, nil
	}
}

func (portal *Portal) unlockedReID(ctx context.Context, target networkid.PortalKey) error {
	err := portal.Bridge.DB.Portal.ReID(ctx, portal.PortalKey, target)
	if err != nil {
		return err
	}
	delete(portal.Bridge.portalsByKey, portal.PortalKey)
	portal.Bridge.portalsByKey[target] = portal
	portal.PortalKey = target
	return nil
}
