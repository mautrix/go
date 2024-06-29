// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/pushrules"
)

// ASIntent implements the bridge ghost API interface using a real Matrix homeserver as the backend.
type ASIntent struct {
	Matrix    *appservice.IntentAPI
	Connector *Connector
}

var _ bridgev2.MatrixAPI = (*ASIntent)(nil)

func (as *ASIntent) SendMessage(ctx context.Context, roomID id.RoomID, eventType event.Type, content *event.Content, ts time.Time) (*mautrix.RespSendEvent, error) {
	// TODO remove this once hungryserv and synapse support sending m.room.redactions directly in all room versions
	if eventType == event.EventRedaction {
		parsedContent := content.Parsed.(*event.RedactionEventContent)
		return as.Matrix.RedactEvent(ctx, roomID, parsedContent.Redacts, mautrix.ReqRedact{
			Reason: parsedContent.Reason,
			Extra:  content.Raw,
		})
	}
	if eventType != event.EventReaction && eventType != event.EventRedaction {
		if encrypted, err := as.Matrix.StateStore.IsEncrypted(ctx, roomID); err != nil {
			return nil, fmt.Errorf("failed to check if room is encrypted: %w", err)
		} else if encrypted {
			if as.Matrix.IsCustomPuppet {
				as.Matrix.AddDoublePuppetValueWithTS(content, ts.UnixMilli())
			}
			err = as.Connector.Crypto.Encrypt(ctx, roomID, eventType, content)
			if err != nil {
				return nil, err
			}
			eventType = event.EventEncrypted
		}
	}
	if ts.IsZero() {
		return as.Matrix.SendMessageEvent(ctx, roomID, eventType, content)
	} else {
		return as.Matrix.SendMassagedMessageEvent(ctx, roomID, eventType, content, ts.UnixMilli())
	}
}

func (as *ASIntent) fillMemberEvent(ctx context.Context, roomID id.RoomID, userID id.UserID, content *event.Content) {
	targetContent := content.Parsed.(*event.MemberEventContent)
	if targetContent.Displayname != "" || targetContent.AvatarURL != "" {
		return
	}
	memberContent, err := as.Matrix.StateStore.TryGetMember(ctx, roomID, userID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("target_user_id", userID).
			Str("membership", string(targetContent.Membership)).
			Msg("Failed to get old member content from state store to fill new membership event")
	} else if memberContent != nil {
		targetContent.Displayname = memberContent.Displayname
		targetContent.AvatarURL = memberContent.AvatarURL
	} else if ghost, err := as.Connector.Bridge.GetGhostByMXID(ctx, userID); err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("target_user_id", userID).
			Str("membership", string(targetContent.Membership)).
			Msg("Failed to get ghost to fill new membership event")
	} else if ghost != nil {
		targetContent.Displayname = ghost.Name
		targetContent.AvatarURL = ghost.AvatarMXC
	} else if profile, err := as.Matrix.GetProfile(ctx, userID); err != nil {
		zerolog.Ctx(ctx).Debug().Err(err).
			Stringer("target_user_id", userID).
			Str("membership", string(targetContent.Membership)).
			Msg("Failed to get profile to fill new membership event")
	} else if profile != nil {
		targetContent.Displayname = profile.DisplayName
		targetContent.AvatarURL = profile.AvatarURL.CUString()
	}
}

func (as *ASIntent) SendState(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, content *event.Content, ts time.Time) (*mautrix.RespSendEvent, error) {
	if eventType == event.StateMember {
		as.fillMemberEvent(ctx, roomID, id.UserID(stateKey), content)
	}
	if ts.IsZero() {
		return as.Matrix.SendStateEvent(ctx, roomID, eventType, stateKey, content)
	} else {
		return as.Matrix.SendMassagedStateEvent(ctx, roomID, eventType, stateKey, content, ts.UnixMilli())
	}
}

func (as *ASIntent) MarkRead(ctx context.Context, roomID id.RoomID, eventID id.EventID, ts time.Time) error {
	extraData := map[string]any{}
	if !ts.IsZero() {
		extraData["ts"] = ts.UnixMilli()
	}
	as.Matrix.AddDoublePuppetValue(extraData)
	req := mautrix.ReqSetReadMarkers{
		Read:            eventID,
		BeeperReadExtra: extraData,
	}
	if as.Matrix.IsCustomPuppet {
		req.FullyRead = eventID
		req.BeeperFullyReadExtra = extraData
	}
	err := as.Matrix.SetReadMarkers(ctx, roomID, &req)
	if err != nil {
		return err
	}
	if as.Matrix.IsCustomPuppet {
		err = as.Matrix.SetRoomAccountData(ctx, roomID, event.AccountDataMarkedUnread.Type, &event.MarkedUnreadEventContent{
			Unread: false,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (as *ASIntent) MarkUnread(ctx context.Context, roomID id.RoomID, unread bool) error {
	return as.Matrix.SetRoomAccountData(ctx, roomID, event.AccountDataMarkedUnread.Type, &event.MarkedUnreadEventContent{
		Unread: unread,
	})
}

func (as *ASIntent) MarkTyping(ctx context.Context, roomID id.RoomID, typingType bridgev2.TypingType, timeout time.Duration) error {
	if typingType != bridgev2.TypingTypeText {
		return nil
	} else if as.Matrix.IsCustomPuppet {
		// Don't send double puppeted typing notifications, there's no good way to prevent echoing them
		return nil
	}
	_, err := as.Matrix.UserTyping(ctx, roomID, timeout > 0, timeout)
	return err
}

func (as *ASIntent) DownloadMedia(ctx context.Context, uri id.ContentURIString, file *event.EncryptedFileInfo) ([]byte, error) {
	if file != nil {
		uri = file.URL
	}
	parsedURI, err := uri.Parse()
	if err != nil {
		return nil, err
	}
	data, err := as.Matrix.DownloadBytes(ctx, parsedURI)
	if err != nil {
		return nil, err
	}
	if file != nil {
		err = file.DecryptInPlace(data)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (as *ASIntent) UploadMedia(ctx context.Context, roomID id.RoomID, data []byte, fileName, mimeType string) (url id.ContentURIString, file *event.EncryptedFileInfo, err error) {
	if roomID != "" {
		var encrypted bool
		if encrypted, err = as.Matrix.StateStore.IsEncrypted(ctx, roomID); err != nil {
			err = fmt.Errorf("failed to check if room is encrypted: %w", err)
			return
		} else if encrypted {
			file = &event.EncryptedFileInfo{
				EncryptedFile: *attachment.NewEncryptedFile(),
			}
			file.EncryptInPlace(data)
			mimeType = "application/octet-stream"
			fileName = ""
		}
	}
	req := mautrix.ReqUploadMedia{
		ContentBytes: data,
		ContentType:  mimeType,
		FileName:     fileName,
	}
	if as.Connector.Config.Homeserver.AsyncMedia {
		var resp *mautrix.RespCreateMXC
		resp, err = as.Matrix.UploadAsync(ctx, req)
		if resp != nil {
			url = resp.ContentURI.CUString()
		}
	} else {
		var resp *mautrix.RespMediaUpload
		resp, err = as.Matrix.UploadMedia(ctx, req)
		if resp != nil {
			url = resp.ContentURI.CUString()
		}
	}
	if file != nil {
		file.URL = url
		url = ""
	}
	return
}

func (as *ASIntent) SetDisplayName(ctx context.Context, name string) error {
	return as.Matrix.SetDisplayName(ctx, name)
}

func (as *ASIntent) SetAvatarURL(ctx context.Context, avatarURL id.ContentURIString) error {
	parsedAvatarURL, err := avatarURL.Parse()
	if err != nil {
		return err
	}
	return as.Matrix.SetAvatarURL(ctx, parsedAvatarURL)
}

func (as *ASIntent) SetExtraProfileMeta(ctx context.Context, data any) error {
	if !as.Connector.SpecVersions.Supports(mautrix.BeeperFeatureArbitraryProfileMeta) {
		return nil
	}
	return as.Matrix.BeeperUpdateProfile(ctx, data)
}

func (as *ASIntent) GetMXID() id.UserID {
	return as.Matrix.UserID
}

func (as *ASIntent) InviteUser(ctx context.Context, roomID id.RoomID, userID id.UserID) error {
	_, err := as.Matrix.InviteUser(ctx, roomID, &mautrix.ReqInviteUser{
		Reason: "",
		UserID: userID,
	})
	return err
}

func (as *ASIntent) EnsureJoined(ctx context.Context, roomID id.RoomID) error {
	err := as.Matrix.EnsureJoined(ctx, roomID)
	if err != nil {
		return err
	}
	if as.Connector.Bot.UserID == as.Matrix.UserID {
		_, err = as.Matrix.State(ctx, roomID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get state after joining room with bot")
		}
	}
	return nil
}

func (as *ASIntent) EnsureInvited(ctx context.Context, roomID id.RoomID, userID id.UserID) error {
	return as.Matrix.EnsureInvited(ctx, roomID, userID)
}

func (as *ASIntent) CreateRoom(ctx context.Context, req *mautrix.ReqCreateRoom) (id.RoomID, error) {
	if as.Connector.Config.Encryption.Default {
		content := &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}
		if rot := as.Connector.Config.Encryption.Rotation; rot.EnableCustom {
			content.RotationPeriodMillis = rot.Milliseconds
			content.RotationPeriodMessages = rot.Messages
		}
		req.InitialState = append(req.InitialState, &event.Event{
			Type: event.StateEncryption,
			Content: event.Content{
				Parsed: content,
			},
		})
	}
	if !as.Connector.Config.Matrix.FederateRooms {
		if req.CreationContent == nil {
			req.CreationContent = make(map[string]any)
		}
		req.CreationContent["m.federate"] = false
	}
	resp, err := as.Matrix.CreateRoom(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.RoomID, nil
}

func (as *ASIntent) DeleteRoom(ctx context.Context, roomID id.RoomID, puppetsOnly bool) error {
	if as.Connector.SpecVersions.Supports(mautrix.BeeperFeatureRoomYeeting) {
		return as.Matrix.BeeperDeleteRoom(ctx, roomID)
	}
	members, err := as.Matrix.JoinedMembers(ctx, roomID)
	if err != nil {
		return fmt.Errorf("failed to get portal members for cleanup: %w", err)
	}
	for member := range members.Joined {
		if member == as.Matrix.UserID {
			continue
		}
		_, isGhost := as.Connector.ParseGhostMXID(member)
		if isGhost {
			_, err = as.Connector.AS.Intent(member).LeaveRoom(ctx, roomID)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Stringer("user_id", member).Msg("Failed to leave room while cleaning up portal")
			}
		} else if !puppetsOnly {
			_, err = as.Matrix.KickUser(ctx, roomID, &mautrix.ReqKickUser{UserID: member, Reason: "Deleting portal"})
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Stringer("user_id", member).Msg("Failed to kick user while cleaning up portal")
			}
		}
	}
	_, err = as.Matrix.LeaveRoom(ctx, roomID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to leave room while cleaning up portal")
	}
	return nil
}

func (as *ASIntent) TagRoom(ctx context.Context, roomID id.RoomID, tag event.RoomTag, isTagged bool) error {
	tags, err := as.Matrix.GetTags(ctx, roomID)
	if err != nil {
		return fmt.Errorf("failed to get room tags: %w", err)
	}
	if isTagged {
		_, alreadyTagged := tags.Tags[tag]
		if alreadyTagged {
			return nil
		}
		err = as.Matrix.AddTagWithCustomData(ctx, roomID, tag, &event.TagMetadata{
			MauDoublePuppetSource: as.Connector.AS.DoublePuppetValue,
		})
		if err != nil {
			return err
		}
	}
	for extraTag := range tags.Tags {
		if extraTag == event.RoomTagFavourite || extraTag == event.RoomTagLowPriority {
			err = as.Matrix.RemoveTag(ctx, roomID, extraTag)
			if err != nil {
				return fmt.Errorf("failed to remove extra tag %s: %w", extraTag, err)
			}
		}
	}
	return nil
}

func (as *ASIntent) MuteRoom(ctx context.Context, roomID id.RoomID, until time.Time) error {
	if !until.IsZero() && until.Before(time.Now()) {
		err := as.Matrix.DeletePushRule(ctx, "global", pushrules.RoomRule, string(roomID))
		// If the push rule doesn't exist, everything is fine
		if errors.Is(err, mautrix.MNotFound) {
			err = nil
		}
		return err
	} else {
		return as.Matrix.PutPushRule(ctx, "global", pushrules.RoomRule, string(roomID), &mautrix.ReqPutPushRule{
			Actions: []pushrules.PushActionType{pushrules.ActionDontNotify},
		})
	}
}
