// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/fallocate"
	"go.mau.fi/util/ptr"
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/pushrules"
)

// ASIntent implements the bridge ghost API interface using a real Matrix homeserver as the backend.
type ASIntent struct {
	Matrix    *appservice.IntentAPI
	Connector *Connector

	dmUpdateLock     sync.Mutex
	directChatsCache event.DirectChatsEventContent
}

var _ bridgev2.MatrixAPI = (*ASIntent)(nil)
var _ bridgev2.MarkAsDMMatrixAPI = (*ASIntent)(nil)

func (as *ASIntent) SendMessage(ctx context.Context, roomID id.RoomID, eventType event.Type, content *event.Content, extra *bridgev2.MatrixSendExtra) (*mautrix.RespSendEvent, error) {
	if extra == nil {
		extra = &bridgev2.MatrixSendExtra{}
	}
	// TODO remove this once hungryserv and synapse support sending m.room.redactions directly in all room versions
	if eventType == event.EventRedaction {
		parsedContent := content.Parsed.(*event.RedactionEventContent)
		as.Matrix.AddDoublePuppetValue(content)
		return as.Matrix.RedactEvent(ctx, roomID, parsedContent.Redacts, mautrix.ReqRedact{
			Reason: parsedContent.Reason,
			Extra:  content.Raw,
		})
	}
	if eventType != event.EventReaction && eventType != event.EventRedaction {
		msgContent, ok := content.Parsed.(*event.MessageEventContent)
		if ok {
			msgContent.AddPerMessageProfileFallback()
		}
		if encrypted, err := as.Matrix.StateStore.IsEncrypted(ctx, roomID); err != nil {
			return nil, fmt.Errorf("failed to check if room is encrypted: %w", err)
		} else if encrypted {
			if as.Connector.Crypto == nil {
				return nil, fmt.Errorf("room is encrypted, but bridge isn't configured to support encryption")
			}
			if as.Matrix.IsCustomPuppet {
				if extra.Timestamp.IsZero() {
					as.Matrix.AddDoublePuppetValue(content)
				} else {
					as.Matrix.AddDoublePuppetValueWithTS(content, extra.Timestamp.UnixMilli())
				}
			}
			err = as.Connector.Crypto.Encrypt(ctx, roomID, eventType, content)
			if err != nil {
				return nil, err
			}
			eventType = event.EventEncrypted
		}
	}
	if extra.Timestamp.IsZero() {
		return as.Matrix.SendMessageEvent(ctx, roomID, eventType, content)
	} else {
		return as.Matrix.SendMassagedMessageEvent(ctx, roomID, eventType, content, extra.Timestamp.UnixMilli())
	}
}

func (as *ASIntent) fillMemberEvent(ctx context.Context, roomID id.RoomID, userID id.UserID, content *event.Content) {
	targetContent, ok := content.Parsed.(*event.MemberEventContent)
	if !ok || targetContent.Displayname != "" || targetContent.AvatarURL != "" {
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

func (as *ASIntent) SendState(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, content *event.Content, ts time.Time) (resp *mautrix.RespSendEvent, err error) {
	if eventType == event.StateMember {
		as.fillMemberEvent(ctx, roomID, id.UserID(stateKey), content)
	}
	if ts.IsZero() {
		resp, err = as.Matrix.SendStateEvent(ctx, roomID, eventType, stateKey, content)
	} else {
		resp, err = as.Matrix.SendMassagedStateEvent(ctx, roomID, eventType, stateKey, content, ts.UnixMilli())
	}
	if err != nil && eventType == event.StateMember {
		var httpErr mautrix.HTTPError
		if errors.As(err, &httpErr) && httpErr.RespError != nil &&
			(strings.Contains(httpErr.RespError.Err, "is already in the room") || strings.Contains(httpErr.RespError.Err, "is already joined to room")) {
			err = as.Matrix.StateStore.SetMembership(ctx, roomID, id.UserID(stateKey), event.MembershipJoin)
		}
	}
	return resp, err
}

func (as *ASIntent) MarkRead(ctx context.Context, roomID id.RoomID, eventID id.EventID, ts time.Time) (err error) {
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
	if as.Matrix.IsCustomPuppet && as.Connector.SpecVersions.Supports(mautrix.BeeperFeatureInboxState) && as.Connector.Config.Homeserver.Software != bridgeconfig.SoftwareHungry {
		err = as.Matrix.SetBeeperInboxState(ctx, roomID, &mautrix.ReqSetBeeperInboxState{
			//MarkedUnread: ptr.Ptr(false),
			ReadMarkers: &req,
		})
	} else {
		err = as.Matrix.SetReadMarkers(ctx, roomID, &req)
		if err == nil && as.Matrix.IsCustomPuppet && as.Connector.Config.Homeserver.Software != bridgeconfig.SoftwareHungry {
			err = as.Matrix.SetRoomAccountData(ctx, roomID, event.AccountDataMarkedUnread.Type, &event.MarkedUnreadEventContent{
				Unread: false,
			})
		}
	}
	return
}

func (as *ASIntent) MarkUnread(ctx context.Context, roomID id.RoomID, unread bool) error {
	if as.Connector.Config.Homeserver.Software == bridgeconfig.SoftwareHungry {
		return nil
	}
	if as.Matrix.IsCustomPuppet && as.Connector.SpecVersions.Supports(mautrix.BeeperFeatureInboxState) {
		return as.Matrix.SetBeeperInboxState(ctx, roomID, &mautrix.ReqSetBeeperInboxState{
			MarkedUnread: ptr.Ptr(unread),
		})
	} else {
		return as.Matrix.SetRoomAccountData(ctx, roomID, event.AccountDataMarkedUnread.Type, &event.MarkedUnreadEventContent{
			Unread: unread,
		})
	}
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

func (as *ASIntent) DownloadMediaToFile(ctx context.Context, uri id.ContentURIString, file *event.EncryptedFileInfo, writable bool, callback func(*os.File) error) error {
	if file != nil {
		uri = file.URL
		err := file.PrepareForDecryption()
		if err != nil {
			return err
		}
	}
	parsedURI, err := uri.Parse()
	if err != nil {
		return err
	}
	tempFile, err := os.CreateTemp("", "mautrix-download-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
	}()
	resp, err := as.Matrix.Download(ctx, parsedURI)
	if err != nil {
		return fmt.Errorf("failed to send download request: %w", err)
	}
	defer resp.Body.Close()
	reader := resp.Body
	if file != nil {
		reader = file.DecryptStream(reader)
	}
	if resp.ContentLength > 0 {
		err = fallocate.Fallocate(tempFile, int(resp.ContentLength))
		if err != nil {
			return fmt.Errorf("failed to preallocate file: %w", err)
		}
	}
	_, err = io.Copy(tempFile, reader)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	err = reader.Close()
	if err != nil {
		return fmt.Errorf("failed to close response body: %w", err)
	}
	_, err = tempFile.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start of temp file: %w", err)
	}
	err = callback(tempFile)
	if err != nil {
		return bridgev2.CallbackError{Type: "read", Wrapped: err}
	}
	return nil
}

func (as *ASIntent) UploadMedia(ctx context.Context, roomID id.RoomID, data []byte, fileName, mimeType string) (url id.ContentURIString, file *event.EncryptedFileInfo, err error) {
	if int64(len(data)) > as.Connector.MediaConfig.UploadSize {
		return "", nil, fmt.Errorf("file too large (%.2f MB > %.2f MB)", float64(len(data))/1000/1000, float64(as.Connector.MediaConfig.UploadSize)/1000/1000)
	}
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
	url, err = as.doUploadReq(ctx, file, mautrix.ReqUploadMedia{
		ContentBytes: data,
		ContentType:  mimeType,
		FileName:     fileName,
	})
	return
}

func (as *ASIntent) UploadMediaStream(
	ctx context.Context,
	roomID id.RoomID,
	size int64,
	requireFile bool,
	cb bridgev2.FileStreamCallback,
) (url id.ContentURIString, file *event.EncryptedFileInfo, err error) {
	if size > as.Connector.MediaConfig.UploadSize {
		return "", nil, fmt.Errorf("file too large (%.2f MB > %.2f MB)", float64(size)/1000/1000, float64(as.Connector.MediaConfig.UploadSize)/1000/1000)
	}
	if !requireFile && 0 < size && size < as.Connector.Config.Matrix.UploadFileThreshold {
		var buf bytes.Buffer
		res, err := cb(&buf)
		if err != nil {
			return "", nil, err
		} else if res.ReplacementFile != "" {
			panic(fmt.Errorf("logic error: replacement path must only be returned if requireFile is true"))
		}
		return as.UploadMedia(ctx, roomID, buf.Bytes(), res.FileName, res.MimeType)
	}
	var tempFile *os.File
	tempFile, err = os.CreateTemp("", "mautrix-upload-*")
	if err != nil {
		err = fmt.Errorf("failed to create temp file: %w", err)
		return
	}
	removeAndClose := func(f *os.File) {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}
	startedAsyncUpload := false
	defer func() {
		if !startedAsyncUpload {
			removeAndClose(tempFile)
		}
	}()
	if size > 0 {
		err = fallocate.Fallocate(tempFile, int(size))
		if err != nil {
			err = fmt.Errorf("failed to preallocate file: %w", err)
			return
		}
	}
	if roomID != "" {
		var encrypted bool
		if encrypted, err = as.Matrix.StateStore.IsEncrypted(ctx, roomID); err != nil {
			err = fmt.Errorf("failed to check if room is encrypted: %w", err)
			return
		} else if encrypted {
			file = &event.EncryptedFileInfo{
				EncryptedFile: *attachment.NewEncryptedFile(),
			}
		}
	}
	var res *bridgev2.FileStreamResult
	res, err = cb(tempFile)
	if err != nil {
		err = bridgev2.CallbackError{Type: "write", Wrapped: err}
		return
	}
	var replFile *os.File
	if res.ReplacementFile != "" {
		replFile, err = os.OpenFile(res.ReplacementFile, os.O_RDWR, 0)
		if err != nil {
			err = fmt.Errorf("failed to open replacement file: %w", err)
			return
		}
		defer func() {
			if !startedAsyncUpload {
				removeAndClose(replFile)
			}
		}()
	} else {
		replFile = tempFile
		_, err = replFile.Seek(0, io.SeekStart)
		if err != nil {
			err = fmt.Errorf("failed to seek to start of temp file: %w", err)
			return
		}
	}
	if file != nil {
		res.FileName = ""
		res.MimeType = "application/octet-stream"
		err = file.EncryptFile(replFile)
		if err != nil {
			err = fmt.Errorf("failed to encrypt file: %w", err)
			return
		}
		_, err = replFile.Seek(0, io.SeekStart)
		if err != nil {
			err = fmt.Errorf("failed to seek to start of temp file after encrypting: %w", err)
			return
		}
	}
	info, err := replFile.Stat()
	if err != nil {
		err = fmt.Errorf("failed to get temp file info: %w", err)
		return
	}
	size = info.Size()
	if size > as.Connector.MediaConfig.UploadSize {
		return "", nil, fmt.Errorf("file too large (%.2f MB > %.2f MB)", float64(size)/1000/1000, float64(as.Connector.MediaConfig.UploadSize)/1000/1000)
	}
	req := mautrix.ReqUploadMedia{
		Content:       replFile,
		ContentLength: size,
		ContentType:   res.MimeType,
		FileName:      res.FileName,
	}
	if as.Connector.Config.Homeserver.AsyncMedia {
		req.DoneCallback = func() {
			removeAndClose(replFile)
			removeAndClose(tempFile)
		}
		startedAsyncUpload = true
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

func (as *ASIntent) doUploadReq(ctx context.Context, file *event.EncryptedFileInfo, req mautrix.ReqUploadMedia) (url id.ContentURIString, err error) {
	if as.Connector.Config.Homeserver.AsyncMedia {
		if req.ContentBytes != nil {
			// Prevent too many background uploads at once
			err = as.Connector.uploadSema.Acquire(ctx, int64(len(req.ContentBytes)))
			if err != nil {
				return
			}
			req.DoneCallback = func() {
				as.Connector.uploadSema.Release(int64(len(req.ContentBytes)))
			}
		}
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

func (as *ASIntent) IsDoublePuppet() bool {
	return as.Matrix.IsDoublePuppet()
}

func (as *ASIntent) EnsureJoined(ctx context.Context, roomID id.RoomID, extra ...bridgev2.EnsureJoinedParams) error {
	var params bridgev2.EnsureJoinedParams
	if len(extra) > 0 {
		params = extra[0]
	}
	err := as.Matrix.EnsureJoined(ctx, roomID, appservice.EnsureJoinedParams{Via: params.Via})
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

func (br *Connector) getDefaultEncryptionEvent() *event.EncryptionEventContent {
	content := &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}
	if rot := br.Config.Encryption.Rotation; rot.EnableCustom {
		content.RotationPeriodMillis = rot.Milliseconds
		content.RotationPeriodMessages = rot.Messages
	}
	return content
}

func (as *ASIntent) CreateRoom(ctx context.Context, req *mautrix.ReqCreateRoom) (id.RoomID, error) {
	if as.Connector.Config.Encryption.Default {
		req.InitialState = append(req.InitialState, &event.Event{
			Type: event.StateEncryption,
			Content: event.Content{
				Parsed: as.Connector.getDefaultEncryptionEvent(),
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

func (as *ASIntent) MarkAsDM(ctx context.Context, roomID id.RoomID, withUser id.UserID) error {
	if !as.Connector.Config.Matrix.SyncDirectChatList {
		return nil
	}
	as.dmUpdateLock.Lock()
	defer as.dmUpdateLock.Unlock()
	cached, ok := as.directChatsCache[withUser]
	if ok && slices.Contains(cached, roomID) {
		return nil
	}
	var directChats event.DirectChatsEventContent
	err := as.Matrix.GetAccountData(ctx, event.AccountDataDirectChats.Type, &directChats)
	if err != nil {
		return err
	}
	as.directChatsCache = directChats
	rooms := directChats[withUser]
	if slices.Contains(rooms, roomID) {
		return nil
	}
	directChats[withUser] = append(rooms, roomID)
	err = as.Matrix.SetAccountData(ctx, event.AccountDataDirectChats.Type, &directChats)
	if err != nil {
		if rooms == nil {
			delete(directChats, withUser)
		} else {
			directChats[withUser] = rooms
		}
		return fmt.Errorf("failed to set direct chats account data: %w", err)
	}
	return nil
}

func (as *ASIntent) DeleteRoom(ctx context.Context, roomID id.RoomID, puppetsOnly bool) error {
	if roomID == "" {
		return nil
	}
	if as.Connector.SpecVersions.Supports(mautrix.BeeperFeatureRoomYeeting) {
		err := as.Matrix.BeeperDeleteRoom(ctx, roomID)
		if err != nil {
			return err
		}
		err = as.Matrix.StateStore.ClearCachedMembers(ctx, roomID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to clear cached members while cleaning up portal")
		}
		return nil
	}
	members, err := as.Matrix.JoinedMembers(ctx, roomID)
	if err != nil {
		return fmt.Errorf("failed to get portal members for cleanup: %w", err)
	}
	for member := range members.Joined {
		if member == as.Matrix.UserID {
			continue
		}
		if as.Connector.Bridge.IsGhostMXID(member) {
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
	err = as.Matrix.StateStore.ClearCachedMembers(ctx, roomID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to clear cached members while cleaning up portal")
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
	var mutedUntil int64
	if until.Before(time.Now()) {
		mutedUntil = 0
	} else if until == event.MutedForever {
		mutedUntil = -1
	} else {
		mutedUntil = until.UnixMilli()
	}
	if as.Connector.SpecVersions.Supports(mautrix.BeeperFeatureAccountDataMute) {
		return as.Matrix.SetRoomAccountData(ctx, roomID, event.AccountDataBeeperMute.Type, &event.BeeperMuteEventContent{
			MutedUntil: mutedUntil,
		})
	}
	if mutedUntil == 0 {
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

func (as *ASIntent) GetEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID) (*event.Event, error) {
	evt, err := as.Matrix.Client.GetEvent(ctx, roomID, eventID)
	if err != nil {
		return nil, err
	}
	err = evt.Content.ParseRaw(evt.Type)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Stringer("room_id", roomID).Stringer("event_id", eventID).Msg("failed to parse event content")
	}

	if evt.Type == event.EventEncrypted {
		if as.Connector.Config.Encryption.DeleteKeys.RatchetOnDecrypt {
			return nil, errors.New("can't decrypt the event")
		}
		return as.Matrix.Crypto.Decrypt(ctx, evt)
	}

	return evt, nil
}
