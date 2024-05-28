// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type MatrixConnector interface {
	Init(*Bridge)
	Start(ctx context.Context) error

	ParseGhostMXID(userID id.UserID) (networkid.UserID, bool)
	FormatGhostMXID(userID networkid.UserID) id.UserID

	GhostIntent(userID id.UserID) MatrixAPI
	UserIntent(user *User) MatrixAPI
	BotIntent() MatrixAPI

	SendMessageStatus(ctx context.Context, status MessageStatus)

	GetMembers(ctx context.Context, roomID id.RoomID) (map[id.UserID]*event.MemberEventContent, error)
	GetMemberInfo(ctx context.Context, roomID id.RoomID, userID id.UserID) (*event.MemberEventContent, error)

	ServerName() string
}

type MatrixAPI interface {
	GetMXID() id.UserID

	SendMessage(ctx context.Context, roomID id.RoomID, eventType event.Type, content *event.Content, ts time.Time) (*mautrix.RespSendEvent, error)
	SendState(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, content *event.Content, ts time.Time) (*mautrix.RespSendEvent, error)
	DownloadMedia(ctx context.Context, uri id.ContentURIString, file *event.EncryptedFileInfo) ([]byte, error)
	UploadMedia(ctx context.Context, roomID id.RoomID, data []byte, fileName, mimeType string) (url id.ContentURIString, file *event.EncryptedFileInfo, err error)

	SetDisplayName(ctx context.Context, name string) error
	SetAvatarURL(ctx context.Context, avatarURL id.ContentURIString) error
	SetExtraProfileMeta(ctx context.Context, data any) error

	CreateRoom(ctx context.Context, req *mautrix.ReqCreateRoom) (id.RoomID, error)
	DeleteRoom(ctx context.Context, roomID id.RoomID) error
	InviteUser(ctx context.Context, roomID id.RoomID, userID id.UserID) error
	EnsureJoined(ctx context.Context, roomID id.RoomID) error
}
