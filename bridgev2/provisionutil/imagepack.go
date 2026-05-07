// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package provisionutil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exmaps"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type RespImagePackSavedToRoom struct {
	EventID   id.EventID   `json:"event_id"`
	RoomID    id.RoomID    `json:"room_id"`
	StateKey  string       `json:"state_key"`
	EventIDs  []id.EventID `json:"event_ids,omitempty"`
	StateKeys []string     `json:"state_keys,omitempty"`
}

type spaceableNetworkAPI interface {
	bridgev2.NetworkAPI
	GetSpaceRoom() id.RoomID
}

func ImportImagePack(ctx context.Context, login *bridgev2.UserLogin, packURL string, saveToRoom bool) (any, error) {
	var spaceRoom id.RoomID
	if saveToRoom {
		var err error
		spaceRoom, err = login.GetSpaceRoom(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get space room for user")
			return nil, bridgev2.RespError(mautrix.MUnknown.WithMessage("Failed to get space room for user"))
		} else if spaceRoom == "" {
			// Small hack to allow importing emojis on Slack where there's a shared team space portal
			// instead of individual personal filtering spaces.
			spaceableAPI, ok := login.Client.(spaceableNetworkAPI)
			if ok && spaceableAPI.GetSpaceRoom() != "" {
				spaceRoom = spaceableAPI.GetSpaceRoom()
			} else {
				return nil, bridgev2.RespError(mautrix.MNotFound.WithMessage("Can't import image pack to space when personal filtering spaces are disabled"))
			}
		}
	}
	api, ok := login.Client.(bridgev2.StickerImportingNetworkAPI)
	if !ok {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support importing image packs"))
	}
	resp, err := api.DownloadImagePack(ctx, packURL)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Str("pack_url", packURL).Msg("Failed to download image pack")
		if !errors.Is(err, mautrix.MNotFound) {
			login.TrackAnalytics("Image Pack Import Fail", map[string]any{})
		}
		return nil, err
	}
	if resp.Shortcode == "" && resp.Content.Metadata.BridgedPack != nil {
		resp.Shortcode = resp.Content.Metadata.BridgedPack.URL
	}
	if saveToRoom {
		var eventIDs []id.EventID
		var stateKeys []string
		packs, err := SplitPack(resp)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to split image pack into multiple state events")
			return nil, fmt.Errorf("failed to split image pack into multiple state events: %w", err)
		}
		if len(packs) > 1 {
			zerolog.Ctx(ctx).Info().
				Int("pack_count", len(packs)).
				Msg("Split pack into parts")
		}
		for i, content := range packs {
			stateKey := resp.Shortcode
			if i > 0 {
				stateKey = fmt.Sprintf("%s.%d", resp.Shortcode, i)
			}
			zerolog.Ctx(ctx).Trace().Str("state_key", stateKey).RawJSON("pack_data", content).Msg("Sending pack")
			sendResp, err := login.Bridge.Bot.SendState(ctx, spaceRoom, event.StateImagePack, stateKey, &event.Content{VeryRaw: content}, time.Now())
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Int("pack_idx", i).Msg("Failed to send image pack state event to space")
				return nil, fmt.Errorf("failed to send image pack state event #%d to space: %w", i+1, err)
			}
			eventIDs = append(eventIDs, sendResp.EventID)
			stateKeys = append(stateKeys, stateKey)
		}
		shortcodeHash := sha256.Sum256([]byte(resp.Shortcode))
		login.TrackAnalytics("Image Pack Imported", map[string]any{
			"shortcode_hash": hex.EncodeToString(shortcodeHash[:16]),
		})
		return &RespImagePackSavedToRoom{
			RoomID:    spaceRoom,
			EventID:   eventIDs[0],
			EventIDs:  eventIDs,
			StateKey:  stateKeys[0],
			StateKeys: stateKeys,
		}, nil
	}
	return &event.Content{
		Parsed: resp.Content,
		Raw:    resp.Extra,
	}, nil
}

var MaxPackBytes = 62 * 1024

func SplitPack(resp *bridgev2.ImportedImagePack) ([]json.RawMessage, error) {
	fullPack, err := json.Marshal(&event.Content{
		Parsed: resp.Content,
		Raw:    resp.Extra,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal base content: %w", err)
	}
	if len(fullPack) < MaxPackBytes {
		return []json.RawMessage{fullPack}, nil
	}

	baseContent := exmaps.NonNilClone(resp.Extra)
	baseContent["pack"] = resp.Content.Metadata
	baseContent["images"] = map[string]json.RawMessage{}
	baseContent["fi.mau.combined_pack_key"] = resp.Shortcode
	baseContent["fi.mau.combined_pack_index"] = 0
	baseContent["fi.mau.combined_pack_count"] = 0
	basePack, err := json.Marshal(baseContent)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal base content: %w", err)
	}

	imageKeys := make([]string, 0, len(resp.Content.Images))
	imageJSONs := make(map[string]json.RawMessage, len(resp.Content.Images))
	for key, image := range resp.Content.Images {
		imageKeys = append(imageKeys, key)
		imageJSONs[key], err = json.Marshal(image)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal %s: %w", key, err)
		}
	}

	slices.Sort(imageKeys)
	currentPackImages := make(map[string]json.RawMessage)
	currentSize := len(basePack)
	packs := make([]map[string]any, 0)
	compilePack := func() {
		if len(currentPackImages) == 0 {
			return
		}
		newPack := maps.Clone(baseContent)
		newPack["images"] = currentPackImages
		newPack["fi.mau.combined_pack_index"] = len(packs)
		meta := resp.Content.Metadata
		meta.DisplayName = fmt.Sprintf("%s (part %d)", meta.DisplayName, len(packs)+1)
		newPack["pack"] = meta
		packs = append(packs, newPack)
		currentPackImages = make(map[string]json.RawMessage)
		currentSize = len(basePack)
	}
	if currentSize > MaxPackBytes/3 {
		return nil, fmt.Errorf("pack metadata is too large: %d bytes", currentSize)
	}
	for _, key := range imageKeys {
		nextImg := imageJSONs[key]
		nextSize := len(nextImg) + len(key) + 4
		if currentSize+nextSize > MaxPackBytes {
			compilePack()
		}
		currentPackImages[key] = nextImg
		currentSize += nextSize
	}
	compilePack()
	packJSONs := make([]json.RawMessage, len(packs))
	for i, pack := range packs {
		pack["fi.mau.combined_pack_count"] = len(packs)
		packJSONs[i], err = json.Marshal(pack)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal pack %d: %w", i, err)
		}
	}
	return packJSONs, err
}

func ListImagePacks(ctx context.Context, login *bridgev2.UserLogin) ([]*event.ImagePackMetadata, error) {
	api, ok := login.Client.(bridgev2.StickerImportingNetworkAPI)
	if !ok {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support importing image packs"))
	}
	return api.ListImagePacks(ctx)
}
