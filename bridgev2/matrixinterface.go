// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"time"

	"github.com/gorilla/mux"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type MatrixCapabilities struct {
	AutoJoinInvites bool
	BatchSending    bool
}

type MatrixConnector interface {
	Init(*Bridge)
	Start(ctx context.Context) error
	Stop()

	GetCapabilities() *MatrixCapabilities

	ParseGhostMXID(userID id.UserID) (networkid.UserID, bool)
	GhostIntent(userID networkid.UserID) MatrixAPI
	NewUserIntent(ctx context.Context, userID id.UserID, accessToken string) (MatrixAPI, string, error)
	BotIntent() MatrixAPI

	SendBridgeStatus(ctx context.Context, state *status.BridgeState) error
	SendMessageStatus(ctx context.Context, status *MessageStatus, evt *MessageStatusEventInfo)

	GenerateContentURI(ctx context.Context, mediaID networkid.MediaID) (id.ContentURIString, error)

	GetPowerLevels(ctx context.Context, roomID id.RoomID) (*event.PowerLevelsEventContent, error)
	GetMembers(ctx context.Context, roomID id.RoomID) (map[id.UserID]*event.MemberEventContent, error)
	GetMemberInfo(ctx context.Context, roomID id.RoomID, userID id.UserID) (*event.MemberEventContent, error)

	BatchSend(ctx context.Context, roomID id.RoomID, req *mautrix.ReqBeeperBatchSend, extras []*MatrixSendExtra) (*mautrix.RespBeeperBatchSend, error)
	GenerateDeterministicEventID(roomID id.RoomID, portalKey networkid.PortalKey, messageID networkid.MessageID, partID networkid.PartID) id.EventID
	GenerateReactionEventID(roomID id.RoomID, targetMessage *database.Message, sender networkid.UserID, emojiID networkid.EmojiID) id.EventID

	ServerName() string
}

type MatrixConnectorWithServer interface {
	GetPublicAddress() string
	GetRouter() *mux.Router
}

type MatrixConnectorWithPublicMedia interface {
	GetPublicMediaAddress(contentURI id.ContentURIString) string
}

type MatrixConnectorWithNameDisambiguation interface {
	IsConfusableName(ctx context.Context, roomID id.RoomID, userID id.UserID, name string) ([]id.UserID, error)
}

type MatrixConnectorWithPostRoomBridgeHandling interface {
	HandleNewlyBridgedRoom(ctx context.Context, roomID id.RoomID) error
}

type MatrixSendExtra struct {
	Timestamp    time.Time
	MessageMeta  *database.Message
	ReactionMeta *database.Reaction
}

type MatrixAPI interface {
	GetMXID() id.UserID

	SendMessage(ctx context.Context, roomID id.RoomID, eventType event.Type, content *event.Content, extra *MatrixSendExtra) (*mautrix.RespSendEvent, error)
	SendState(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, content *event.Content, ts time.Time) (*mautrix.RespSendEvent, error)
	MarkRead(ctx context.Context, roomID id.RoomID, eventID id.EventID, ts time.Time) error
	MarkUnread(ctx context.Context, roomID id.RoomID, unread bool) error
	MarkTyping(ctx context.Context, roomID id.RoomID, typingType TypingType, timeout time.Duration) error
	DownloadMedia(ctx context.Context, uri id.ContentURIString, file *event.EncryptedFileInfo) ([]byte, error)
	UploadMedia(ctx context.Context, roomID id.RoomID, data []byte, fileName, mimeType string) (url id.ContentURIString, file *event.EncryptedFileInfo, err error)

	SetDisplayName(ctx context.Context, name string) error
	SetAvatarURL(ctx context.Context, avatarURL id.ContentURIString) error
	SetExtraProfileMeta(ctx context.Context, data any) error

	CreateRoom(ctx context.Context, req *mautrix.ReqCreateRoom) (id.RoomID, error)
	DeleteRoom(ctx context.Context, roomID id.RoomID, puppetsOnly bool) error
	InviteUser(ctx context.Context, roomID id.RoomID, userID id.UserID) error
	EnsureJoined(ctx context.Context, roomID id.RoomID) error
	EnsureInvited(ctx context.Context, roomID id.RoomID, userID id.UserID) error

	TagRoom(ctx context.Context, roomID id.RoomID, tag event.RoomTag, isTagged bool) error
	MuteRoom(ctx context.Context, roomID id.RoomID, until time.Time) error
}

type MarkAsDMMatrixAPI interface {
	MarkAsDM(ctx context.Context, roomID id.RoomID, otherUser id.UserID) error
}
