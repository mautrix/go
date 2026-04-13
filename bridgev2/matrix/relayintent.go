// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"fmt"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type RelayIntent struct {
	*ASIntent
	ID    networkid.UserID
	ghost *bridgev2.Ghost
}

var _ bridgev2.MatrixAPI = (*RelayIntent)(nil)

func (as *RelayIntent) SendMessage(ctx context.Context, roomID id.RoomID, eventType event.Type, content *event.Content, extra *bridgev2.MatrixSendExtra) (*mautrix.RespSendEvent, error) {
	if as.ghost == nil {
		var err error
		as.ghost, err = as.Connector.Bridge.GetExistingGhostByID(ctx, as.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get ghost for relay intent: %w", err)
		}
	}
	msgContent, ok := content.Parsed.(*event.MessageEventContent)
	if ok {
		msgContent.RemovePerMessageProfileFallback()
		if msgContent.NewContent != nil {
			msgContent = msgContent.NewContent
		}
		if msgContent.BeeperPerMessageProfile == nil {
			msgContent.BeeperPerMessageProfile = &event.BeeperPerMessageProfile{}
		}
		pmp := msgContent.BeeperPerMessageProfile
		if pmp.ID != "" {
			pmp.ID = fmt.Sprintf("%s/%s", as.ID, pmp.ID)
		} else {
			pmp.ID = string(as.ID)
		}
		if pmp.Displayname == "" {
			pmp.Displayname = as.ghost.Name
		}
		if pmp.AvatarURL == nil && pmp.AvatarFile == nil {
			pmp.AvatarURL = &as.ghost.AvatarMXC
		}
		msgContent.AddPerMessageProfileFallback()
	} else {
		content.Raw["com.beeper.per_message_profile"] = &event.BeeperPerMessageProfile{
			ID:          string(as.ID),
			Displayname: as.ghost.Name,
			AvatarURL:   &as.ghost.AvatarMXC,
		}
	}
	return as.ASIntent.SendMessage(ctx, roomID, eventType, content, extra)
}

func (as *RelayIntent) SendState(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, content *event.Content, ts time.Time) (resp *mautrix.RespSendEvent, err error) {
	if as.ghost == nil {
		as.ghost, err = as.Connector.Bridge.GetExistingGhostByID(ctx, as.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get ghost for relay intent: %w", err)
		}
	}
	content.Raw["com.beeper.per_message_profile"] = &event.BeeperPerMessageProfile{
		ID:          string(as.ID),
		Displayname: as.ghost.Name,
		AvatarURL:   &as.ghost.AvatarMXC,
	}
	return as.ASIntent.SendState(ctx, roomID, eventType, stateKey, content, ts)
}

func (as *RelayIntent) MarkRead(ctx context.Context, roomID id.RoomID, eventID id.EventID, ts time.Time) error {
	return nil
}

func (as *RelayIntent) MarkUnread(ctx context.Context, roomID id.RoomID, unread bool) error {
	return nil
}

func (as *RelayIntent) MarkTyping(ctx context.Context, roomID id.RoomID, typingType bridgev2.TypingType, timeout time.Duration) error {
	return nil
}

func (as *RelayIntent) SetDisplayName(ctx context.Context, name string) error {
	return nil
}

func (as *RelayIntent) SetAvatarURL(ctx context.Context, avatarURL id.ContentURIString) error {
	return nil
}

func (as *RelayIntent) SetProfile(ctx context.Context, data any) error {
	return nil
}

func (as *RelayIntent) SetExtraProfileMeta(ctx context.Context, data any) error {
	return nil
}

func (as *RelayIntent) GetMXID() id.UserID {
	// TODO make sure this doesn't explode anything
	return ""
}

func (as *RelayIntent) IsDoublePuppet() bool {
	return false
}

func (as *RelayIntent) EnsureJoined(ctx context.Context, roomID id.RoomID, extra ...bridgev2.EnsureJoinedParams) error {
	return nil
}

func (as *RelayIntent) EnsureInvited(ctx context.Context, roomID id.RoomID, userID id.UserID) error {
	return fmt.Errorf("can't use EnsureInvited on relay intent")
}

func (as *RelayIntent) MarkAsDM(ctx context.Context, roomID id.RoomID, withUser id.UserID) error {
	return fmt.Errorf("can't use MarkAsDM on relay intent")
}

func (as *RelayIntent) TagRoom(ctx context.Context, roomID id.RoomID, tag event.RoomTag, isTagged bool) error {
	return fmt.Errorf("can't use TagRoom on relay intent")
}

func (as *RelayIntent) MuteRoom(ctx context.Context, roomID id.RoomID, until time.Time) error {
	return fmt.Errorf("can't use MuteRoom on relay intent")
}
