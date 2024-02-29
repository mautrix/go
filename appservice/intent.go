// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
)

type IntentAPI struct {
	*mautrix.Client
	bot       *mautrix.Client
	as        *AppService
	Localpart string
	UserID    id.UserID

	registerLock sync.Mutex

	IsCustomPuppet bool
}

func (as *AppService) NewIntentAPI(localpart string) *IntentAPI {
	userID := id.NewUserID(localpart, as.HomeserverDomain)
	bot := as.BotClient()
	if userID == bot.UserID {
		bot = nil
	}
	return &IntentAPI{
		Client:    as.Client(userID),
		bot:       bot,
		as:        as,
		Localpart: localpart,
		UserID:    userID,

		IsCustomPuppet: false,
	}
}

func (intent *IntentAPI) Register(ctx context.Context) error {
	_, _, err := intent.Client.Register(ctx, &mautrix.ReqRegister{
		Username:     intent.Localpart,
		Type:         mautrix.AuthTypeAppservice,
		InhibitLogin: true,
	})
	return err
}

func (intent *IntentAPI) EnsureRegistered(ctx context.Context) error {
	if intent.IsCustomPuppet {
		return nil
	}
	intent.registerLock.Lock()
	defer intent.registerLock.Unlock()
	isRegistered, err := intent.as.StateStore.IsRegistered(ctx, intent.UserID)
	if err != nil {
		return fmt.Errorf("failed to check if user is registered: %w", err)
	} else if isRegistered {
		return nil
	}

	err = intent.Register(ctx)
	if err != nil && !errors.Is(err, mautrix.MUserInUse) {
		return fmt.Errorf("failed to ensure registered: %w", err)
	}
	err = intent.as.StateStore.MarkRegistered(ctx, intent.UserID)
	if err != nil {
		return fmt.Errorf("failed to mark user as registered in state store: %w", err)
	}
	return nil
}

type EnsureJoinedParams struct {
	IgnoreCache bool
	BotOverride *mautrix.Client
}

func (intent *IntentAPI) EnsureJoined(ctx context.Context, roomID id.RoomID, extra ...EnsureJoinedParams) error {
	var params EnsureJoinedParams
	if len(extra) > 1 {
		panic("invalid number of extra parameters")
	} else if len(extra) == 1 {
		params = extra[0]
	}
	if intent.as.StateStore.IsInRoom(ctx, roomID, intent.UserID) && !params.IgnoreCache {
		return nil
	}

	if err := intent.EnsureRegistered(ctx); err != nil {
		return fmt.Errorf("failed to ensure joined: %w", err)
	}

	resp, err := intent.JoinRoomByID(ctx, roomID)
	if err != nil {
		bot := intent.bot
		if params.BotOverride != nil {
			bot = params.BotOverride
		}
		if !errors.Is(err, mautrix.MForbidden) || bot == nil {
			return fmt.Errorf("failed to ensure joined: %w", err)
		}
		_, inviteErr := bot.InviteUser(ctx, roomID, &mautrix.ReqInviteUser{
			UserID: intent.UserID,
		})
		if inviteErr != nil {
			return fmt.Errorf("failed to invite in ensure joined: %w", inviteErr)
		}
		resp, err = intent.JoinRoomByID(ctx, roomID)
		if err != nil {
			return fmt.Errorf("failed to ensure joined after invite: %w", err)
		}
	}
	err = intent.as.StateStore.SetMembership(ctx, resp.RoomID, intent.UserID, event.MembershipJoin)
	if err != nil {
		return fmt.Errorf("failed to set membership in state store: %w", err)
	}
	return nil
}

func (intent *IntentAPI) AddDoublePuppetValue(into interface{}) interface{} {
	if !intent.IsCustomPuppet || intent.as.DoublePuppetValue == "" {
		return into
	}
	switch val := into.(type) {
	case *map[string]interface{}:
		if *val == nil {
			valNonPtr := make(map[string]interface{})
			*val = valNonPtr
		}
		(*val)[DoublePuppetKey] = intent.as.DoublePuppetValue
		return val
	case map[string]interface{}:
		val[DoublePuppetKey] = intent.as.DoublePuppetValue
		return val
	case *event.Content:
		if val.Raw == nil {
			val.Raw = make(map[string]interface{})
		}
		val.Raw[DoublePuppetKey] = intent.as.DoublePuppetValue
		return val
	case event.Content:
		if val.Raw == nil {
			val.Raw = make(map[string]interface{})
		}
		val.Raw[DoublePuppetKey] = intent.as.DoublePuppetValue
		return val
	default:
		return &event.Content{
			Raw: map[string]interface{}{
				DoublePuppetKey: intent.as.DoublePuppetValue,
			},
			Parsed: val,
		}
	}
}

func (intent *IntentAPI) SendMessageEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, contentJSON interface{}) (*mautrix.RespSendEvent, error) {
	if err := intent.EnsureJoined(ctx, roomID); err != nil {
		return nil, err
	}
	contentJSON = intent.AddDoublePuppetValue(contentJSON)
	return intent.Client.SendMessageEvent(ctx, roomID, eventType, contentJSON)
}

func (intent *IntentAPI) SendMassagedMessageEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, contentJSON interface{}, ts int64) (*mautrix.RespSendEvent, error) {
	if err := intent.EnsureJoined(ctx, roomID); err != nil {
		return nil, err
	}
	contentJSON = intent.AddDoublePuppetValue(contentJSON)
	return intent.Client.SendMessageEvent(ctx, roomID, eventType, contentJSON, mautrix.ReqSendEvent{Timestamp: ts})
}

func (intent *IntentAPI) SendStateEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, contentJSON interface{}) (*mautrix.RespSendEvent, error) {
	if eventType != event.StateMember || stateKey != string(intent.UserID) {
		if err := intent.EnsureJoined(ctx, roomID); err != nil {
			return nil, err
		}
	}
	contentJSON = intent.AddDoublePuppetValue(contentJSON)
	return intent.Client.SendStateEvent(ctx, roomID, eventType, stateKey, contentJSON)
}

func (intent *IntentAPI) SendMassagedStateEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, contentJSON interface{}, ts int64) (*mautrix.RespSendEvent, error) {
	if err := intent.EnsureJoined(ctx, roomID); err != nil {
		return nil, err
	}
	contentJSON = intent.AddDoublePuppetValue(contentJSON)
	return intent.Client.SendMassagedStateEvent(ctx, roomID, eventType, stateKey, contentJSON, ts)
}

func (intent *IntentAPI) StateEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, outContent interface{}) error {
	if err := intent.EnsureJoined(ctx, roomID); err != nil {
		return err
	}
	return intent.Client.StateEvent(ctx, roomID, eventType, stateKey, outContent)
}

func (intent *IntentAPI) State(ctx context.Context, roomID id.RoomID) (mautrix.RoomStateMap, error) {
	if err := intent.EnsureJoined(ctx, roomID); err != nil {
		return nil, err
	}
	return intent.Client.State(ctx, roomID)
}

func (intent *IntentAPI) SendCustomMembershipEvent(ctx context.Context, roomID id.RoomID, target id.UserID, membership event.Membership, reason string, extraContent ...map[string]interface{}) (*mautrix.RespSendEvent, error) {
	content := &event.MemberEventContent{
		Membership: membership,
		Reason:     reason,
	}
	memberContent, err := intent.as.StateStore.TryGetMember(ctx, roomID, target)
	if err != nil {
		return nil, fmt.Errorf("failed to get old member content from state store: %w", err)
	} else if memberContent == nil {
		if intent.as.GetProfile != nil {
			memberContent = intent.as.GetProfile(target, roomID)
		}
		if memberContent == nil {
			profile, err := intent.GetProfile(ctx, target)
			if err != nil {
				intent.Log.Debug().Err(err).
					Str("target_user_id", target.String()).
					Str("membership", string(membership)).
					Msg("Failed to get profile to fill new membership event")
			} else {
				content.Displayname = profile.DisplayName
				content.AvatarURL = profile.AvatarURL.CUString()
			}
		}
	}
	if memberContent != nil {
		content.Displayname = memberContent.Displayname
		content.AvatarURL = memberContent.AvatarURL
	}
	var extra map[string]interface{}
	if len(extraContent) > 0 {
		extra = extraContent[0]
	}
	return intent.SendStateEvent(ctx, roomID, event.StateMember, target.String(), &event.Content{
		Parsed: content,
		Raw:    extra,
	})
}

func (intent *IntentAPI) JoinRoomByID(ctx context.Context, roomID id.RoomID, extraContent ...map[string]interface{}) (resp *mautrix.RespJoinRoom, err error) {
	if intent.IsCustomPuppet || len(extraContent) > 0 {
		_, err = intent.SendCustomMembershipEvent(ctx, roomID, intent.UserID, event.MembershipJoin, "", extraContent...)
		return &mautrix.RespJoinRoom{}, err
	}
	return intent.Client.JoinRoomByID(ctx, roomID)
}

func (intent *IntentAPI) LeaveRoom(ctx context.Context, roomID id.RoomID, extra ...interface{}) (resp *mautrix.RespLeaveRoom, err error) {
	var extraContent map[string]interface{}
	leaveReq := &mautrix.ReqLeave{}
	for _, item := range extra {
		switch val := item.(type) {
		case map[string]interface{}:
			extraContent = val
		case *mautrix.ReqLeave:
			leaveReq = val
		}
	}
	if intent.IsCustomPuppet || extraContent != nil {
		_, err = intent.SendCustomMembershipEvent(ctx, roomID, intent.UserID, event.MembershipLeave, leaveReq.Reason, extraContent)
		return &mautrix.RespLeaveRoom{}, err
	}
	return intent.Client.LeaveRoom(ctx, roomID, leaveReq)
}

func (intent *IntentAPI) InviteUser(ctx context.Context, roomID id.RoomID, req *mautrix.ReqInviteUser, extraContent ...map[string]interface{}) (resp *mautrix.RespInviteUser, err error) {
	if intent.IsCustomPuppet || len(extraContent) > 0 {
		_, err = intent.SendCustomMembershipEvent(ctx, roomID, req.UserID, event.MembershipInvite, req.Reason, extraContent...)
		return &mautrix.RespInviteUser{}, err
	}
	return intent.Client.InviteUser(ctx, roomID, req)
}

func (intent *IntentAPI) KickUser(ctx context.Context, roomID id.RoomID, req *mautrix.ReqKickUser, extraContent ...map[string]interface{}) (resp *mautrix.RespKickUser, err error) {
	if intent.IsCustomPuppet || len(extraContent) > 0 {
		_, err = intent.SendCustomMembershipEvent(ctx, roomID, req.UserID, event.MembershipLeave, req.Reason, extraContent...)
		return &mautrix.RespKickUser{}, err
	}
	return intent.Client.KickUser(ctx, roomID, req)
}

func (intent *IntentAPI) BanUser(ctx context.Context, roomID id.RoomID, req *mautrix.ReqBanUser, extraContent ...map[string]interface{}) (resp *mautrix.RespBanUser, err error) {
	if intent.IsCustomPuppet || len(extraContent) > 0 {
		_, err = intent.SendCustomMembershipEvent(ctx, roomID, req.UserID, event.MembershipBan, req.Reason, extraContent...)
		return &mautrix.RespBanUser{}, err
	}
	return intent.Client.BanUser(ctx, roomID, req)
}

func (intent *IntentAPI) UnbanUser(ctx context.Context, roomID id.RoomID, req *mautrix.ReqUnbanUser, extraContent ...map[string]interface{}) (resp *mautrix.RespUnbanUser, err error) {
	if intent.IsCustomPuppet || len(extraContent) > 0 {
		_, err = intent.SendCustomMembershipEvent(ctx, roomID, req.UserID, event.MembershipLeave, req.Reason, extraContent...)
		return &mautrix.RespUnbanUser{}, err
	}
	return intent.Client.UnbanUser(ctx, roomID, req)
}

func (intent *IntentAPI) Member(ctx context.Context, roomID id.RoomID, userID id.UserID) *event.MemberEventContent {
	member, err := intent.as.StateStore.TryGetMember(ctx, roomID, userID)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).
			Str("room_id", roomID.String()).
			Str("user_id", userID.String()).
			Msg("Failed to get member from state store")
	}
	if member == nil {
		_ = intent.StateEvent(ctx, roomID, event.StateMember, string(userID), &member)
	}
	return member
}

func (intent *IntentAPI) PowerLevels(ctx context.Context, roomID id.RoomID) (pl *event.PowerLevelsEventContent, err error) {
	pl, err = intent.as.StateStore.GetPowerLevels(ctx, roomID)
	if err != nil {
		err = fmt.Errorf("failed to get cached power levels: %w", err)
		return
	}
	if pl == nil {
		pl = &event.PowerLevelsEventContent{}
		err = intent.StateEvent(ctx, roomID, event.StatePowerLevels, "", pl)
	}
	return
}

func (intent *IntentAPI) SetPowerLevels(ctx context.Context, roomID id.RoomID, levels *event.PowerLevelsEventContent) (resp *mautrix.RespSendEvent, err error) {
	return intent.SendStateEvent(ctx, roomID, event.StatePowerLevels, "", &levels)
}

func (intent *IntentAPI) SetPowerLevel(ctx context.Context, roomID id.RoomID, userID id.UserID, level int) (*mautrix.RespSendEvent, error) {
	pl, err := intent.PowerLevels(ctx, roomID)
	if err != nil {
		return nil, err
	}

	if pl.GetUserLevel(userID) != level {
		pl.SetUserLevel(userID, level)
		return intent.SendStateEvent(ctx, roomID, event.StatePowerLevels, "", &pl)
	}
	return nil, nil
}

func (intent *IntentAPI) SendText(ctx context.Context, roomID id.RoomID, text string) (*mautrix.RespSendEvent, error) {
	if err := intent.EnsureJoined(ctx, roomID); err != nil {
		return nil, err
	}
	return intent.Client.SendText(ctx, roomID, text)
}

func (intent *IntentAPI) SendNotice(ctx context.Context, roomID id.RoomID, text string) (*mautrix.RespSendEvent, error) {
	if err := intent.EnsureJoined(ctx, roomID); err != nil {
		return nil, err
	}
	return intent.Client.SendNotice(ctx, roomID, text)
}

func (intent *IntentAPI) RedactEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID, extra ...mautrix.ReqRedact) (*mautrix.RespSendEvent, error) {
	if err := intent.EnsureJoined(ctx, roomID); err != nil {
		return nil, err
	}
	var req mautrix.ReqRedact
	if len(extra) > 0 {
		req = extra[0]
	}
	intent.AddDoublePuppetValue(&req.Extra)
	return intent.Client.RedactEvent(ctx, roomID, eventID, req)
}

func (intent *IntentAPI) SetRoomName(ctx context.Context, roomID id.RoomID, roomName string) (*mautrix.RespSendEvent, error) {
	return intent.SendStateEvent(ctx, roomID, event.StateRoomName, "", map[string]interface{}{
		"name": roomName,
	})
}

func (intent *IntentAPI) SetRoomAvatar(ctx context.Context, roomID id.RoomID, avatarURL id.ContentURI) (*mautrix.RespSendEvent, error) {
	return intent.SendStateEvent(ctx, roomID, event.StateRoomAvatar, "", map[string]interface{}{
		"url": avatarURL.String(),
	})
}

func (intent *IntentAPI) SetRoomTopic(ctx context.Context, roomID id.RoomID, topic string) (*mautrix.RespSendEvent, error) {
	return intent.SendStateEvent(ctx, roomID, event.StateTopic, "", map[string]interface{}{
		"topic": topic,
	})
}

func (intent *IntentAPI) SetDisplayName(ctx context.Context, displayName string) error {
	if err := intent.EnsureRegistered(ctx); err != nil {
		return err
	}
	resp, err := intent.Client.GetOwnDisplayName(ctx)
	if err != nil {
		return fmt.Errorf("failed to check current displayname: %w", err)
	} else if resp.DisplayName == displayName {
		// No need to update
		return nil
	}
	return intent.Client.SetDisplayName(ctx, displayName)
}

func (intent *IntentAPI) SetAvatarURL(ctx context.Context, avatarURL id.ContentURI) error {
	if err := intent.EnsureRegistered(ctx); err != nil {
		return err
	}
	resp, err := intent.Client.GetOwnAvatarURL(ctx)
	if err != nil {
		return fmt.Errorf("failed to check current avatar URL: %w", err)
	} else if resp.FileID == avatarURL.FileID && resp.Homeserver == avatarURL.Homeserver {
		// No need to update
		return nil
	}
	if !avatarURL.IsEmpty() {
		// Some homeservers require the avatar to be downloaded before setting it
		body, _ := intent.Client.Download(ctx, avatarURL)
		if body != nil {
			_ = body.Close()
		}
	}
	return intent.Client.SetAvatarURL(ctx, avatarURL)
}

func (intent *IntentAPI) Whoami(ctx context.Context) (*mautrix.RespWhoami, error) {
	if err := intent.EnsureRegistered(ctx); err != nil {
		return nil, err
	}
	return intent.Client.Whoami(ctx)
}

func (intent *IntentAPI) EnsureInvited(ctx context.Context, roomID id.RoomID, userID id.UserID) error {
	if !intent.as.StateStore.IsInvited(ctx, roomID, userID) {
		_, err := intent.InviteUser(ctx, roomID, &mautrix.ReqInviteUser{
			UserID: userID,
		})
		if httpErr, ok := err.(mautrix.HTTPError); ok &&
			httpErr.RespError != nil &&
			(strings.Contains(httpErr.RespError.Err, "is already in the room") || strings.Contains(httpErr.RespError.Err, "is already joined to room")) {
			return nil
		}
		return err
	}
	return nil
}
