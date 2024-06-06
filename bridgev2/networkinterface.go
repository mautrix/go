// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
)

type ConvertedMessagePart struct {
	ID         networkid.PartID
	Type       event.Type
	Content    *event.MessageEventContent
	Extra      map[string]any
	DBMetadata map[string]any
}

type EventSender struct {
	IsFromMe    bool
	SenderLogin networkid.UserLoginID
	Sender      networkid.UserID
}

type ConvertedMessage struct {
	// TODO are these ever ambiguous at the time of forming the RemoteMessage?
	//ID networkid.MessageID
	//EventSender
	Timestamp  time.Time
	ReplyTo    *networkid.MessageOptionalPartID
	ThreadRoot *networkid.MessageOptionalPartID
	Parts      []*ConvertedMessagePart
}

type ConvertedEditPart struct {
	Part *database.Message

	Type    event.Type
	Content *event.MessageEventContent
	Extra   map[string]any
}

type ConvertedEdit struct {
	Timestamp     time.Time
	ModifiedParts []*ConvertedEditPart
	DeletedParts  []*database.Message
}

type NetworkConnector interface {
	Init(*Bridge)
	Start(context.Context) error
	LoadUserLogin(ctx context.Context, login *UserLogin) error

	GetLoginFlows() []LoginFlow
	CreateLogin(ctx context.Context, user *User, flowID string) (LoginProcess, error)
}

type NetworkAPI interface {
	Connect(ctx context.Context) error
	IsLoggedIn() bool
	LogoutRemote(ctx context.Context)

	IsThisUser(ctx context.Context, userID networkid.UserID) bool
	GetChatInfo(ctx context.Context, portal *Portal) (*PortalInfo, error)
	GetUserInfo(ctx context.Context, ghost *Ghost) (*UserInfo, error)

	HandleMatrixMessage(ctx context.Context, msg *MatrixMessage) (message *database.Message, err error)
	HandleMatrixEdit(ctx context.Context, msg *MatrixEdit) error
	HandleMatrixReaction(ctx context.Context, msg *MatrixReaction) (reaction *database.Reaction, err error)
	HandleMatrixReactionRemove(ctx context.Context, msg *MatrixReactionRemove) error
	HandleMatrixMessageRemove(ctx context.Context, msg *MatrixMessageRemove) error
}

type RemoteEventType int

const (
	RemoteEventMessage RemoteEventType = iota
	RemoteEventEdit
	RemoteEventReaction
	RemoteEventReactionRemove
	RemoteEventMessageRemove
)

type RemoteEvent interface {
	GetType() RemoteEventType
	GetPortalID() networkid.PortalID
	ShouldCreatePortal() bool
	AddLogContext(c zerolog.Context) zerolog.Context
	GetSender() EventSender
}

type RemoteMessage interface {
	RemoteEvent
	GetID() networkid.MessageID
	ConvertMessage(ctx context.Context, portal *Portal, intent MatrixAPI) (*ConvertedMessage, error)
}

type RemoteEdit interface {
	RemoteEvent
	GetTargetMessage() networkid.MessageID
	ConvertEdit(ctx context.Context, portal *Portal, intent MatrixAPI, existing []*database.Message) (*ConvertedEdit, error)
}

type RemoteReaction interface {
	RemoteEvent
	GetTargetMessage() networkid.MessageID
	GetReactionEmoji() (string, networkid.EmojiID)
}

type RemoteReactionRemove interface {
	RemoteEvent
	GetTargetMessage() networkid.MessageID
	GetRemovedEmojiID() networkid.EmojiID
}

type RemoteMessageRemove interface {
	RemoteEvent
	GetTargetMessage() networkid.MessageID
}

// SimpleRemoteEvent is a simple implementation of RemoteEvent that can be used with struct fields and some callbacks.
type SimpleRemoteEvent[T any] struct {
	Type         RemoteEventType
	LogContext   func(c zerolog.Context) zerolog.Context
	PortalID     networkid.PortalID
	Data         T
	CreatePortal bool

	ID            networkid.MessageID
	Sender        EventSender
	TargetMessage networkid.MessageID
	EmojiID       networkid.EmojiID
	Emoji         string

	ConvertMessageFunc func(ctx context.Context, portal *Portal, intent MatrixAPI, data T) (*ConvertedMessage, error)
	ConvertEditFunc    func(ctx context.Context, portal *Portal, intent MatrixAPI, existing []*database.Message, data T) (*ConvertedEdit, error)
}

var (
	_ RemoteMessage        = (*SimpleRemoteEvent[any])(nil)
	_ RemoteEdit           = (*SimpleRemoteEvent[any])(nil)
	_ RemoteReaction       = (*SimpleRemoteEvent[any])(nil)
	_ RemoteReactionRemove = (*SimpleRemoteEvent[any])(nil)
	_ RemoteMessageRemove  = (*SimpleRemoteEvent[any])(nil)
)

func (sre *SimpleRemoteEvent[T]) AddLogContext(c zerolog.Context) zerolog.Context {
	return sre.LogContext(c)
}

func (sre *SimpleRemoteEvent[T]) GetPortalID() networkid.PortalID {
	return sre.PortalID
}

func (sre *SimpleRemoteEvent[T]) ConvertMessage(ctx context.Context, portal *Portal, intent MatrixAPI) (*ConvertedMessage, error) {
	return sre.ConvertMessageFunc(ctx, portal, intent, sre.Data)
}

func (sre *SimpleRemoteEvent[T]) ConvertEdit(ctx context.Context, portal *Portal, intent MatrixAPI, existing []*database.Message) (*ConvertedEdit, error) {
	return sre.ConvertEditFunc(ctx, portal, intent, existing, sre.Data)
}

func (sre *SimpleRemoteEvent[T]) GetID() networkid.MessageID {
	return sre.ID
}

func (sre *SimpleRemoteEvent[T]) GetSender() EventSender {
	return sre.Sender
}

func (sre *SimpleRemoteEvent[T]) GetTargetMessage() networkid.MessageID {
	return sre.TargetMessage
}

func (sre *SimpleRemoteEvent[T]) GetReactionEmoji() (string, networkid.EmojiID) {
	return sre.Emoji, sre.EmojiID
}

func (sre *SimpleRemoteEvent[T]) GetRemovedEmojiID() networkid.EmojiID {
	return sre.EmojiID
}

func (sre *SimpleRemoteEvent[T]) GetType() RemoteEventType {
	return sre.Type
}

func (sre *SimpleRemoteEvent[T]) ShouldCreatePortal() bool {
	return sre.CreatePortal
}

type OrigSender struct {
	User *User
	event.MemberEventContent
}

type MatrixEventBase[ContentType any] struct {
	// The raw event being bridged.
	Event *event.Event
	// The parsed content struct of the event. Custom fields can be found in Event.Content.Raw.
	Content ContentType
	// The room where the event happened.
	Portal *Portal

	// The original sender user ID. Only present in case the event is being relayed (and Sender is not the same user).
	OrigSender *OrigSender
}

type MatrixMessage struct {
	MatrixEventBase[*event.MessageEventContent]
	ThreadRoot *database.Message
	ReplyTo    *database.Message
}

type MatrixEdit struct {
	MatrixEventBase[*event.MessageEventContent]
	EditTarget *database.Message
}

type MatrixReaction struct {
	MatrixEventBase[*event.ReactionEventContent]
	TargetMessage *database.Message
	GetExisting   func(ctx context.Context, senderID networkid.UserID, emojiID networkid.EmojiID) (*database.Reaction, error)
}

type MatrixReactionRemove struct {
	MatrixEventBase[*event.RedactionEventContent]
	TargetReaction *database.Reaction
}

type MatrixMessageRemove struct {
	MatrixEventBase[*event.RedactionEventContent]
	TargetMessage *database.Message
}
