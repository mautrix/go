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
)

// SimpleRemoteEvent is a simple implementation of RemoteEvent that can be used with struct fields and some callbacks.
//
// Using this type is only recommended for simple bridges. More advanced ones should implement
// the remote event interfaces themselves by wrapping the remote network library event types.
//
// Deprecated: use the types in the simplevent package instead.
type SimpleRemoteEvent[T any] struct {
	Type         RemoteEventType
	LogContext   func(c zerolog.Context) zerolog.Context
	PortalKey    networkid.PortalKey
	Data         T
	CreatePortal bool

	ID             networkid.MessageID
	Sender         EventSender
	TargetMessage  networkid.MessageID
	EmojiID        networkid.EmojiID
	Emoji          string
	ReactionDBMeta any
	Timestamp      time.Time
	ChatInfoChange *ChatInfoChange

	ResyncChatInfo       *ChatInfo
	ResyncBackfillNeeded bool

	BackfillData *FetchMessagesResponse

	ConvertMessageFunc func(ctx context.Context, portal *Portal, intent MatrixAPI, data T) (*ConvertedMessage, error)
	ConvertEditFunc    func(ctx context.Context, portal *Portal, intent MatrixAPI, existing []*database.Message, data T) (*ConvertedEdit, error)
}

var (
	_ RemoteMessage            = (*SimpleRemoteEvent[any])(nil)
	_ RemoteEdit               = (*SimpleRemoteEvent[any])(nil)
	_ RemoteEventWithTimestamp = (*SimpleRemoteEvent[any])(nil)
	_ RemoteReaction           = (*SimpleRemoteEvent[any])(nil)
	_ RemoteReactionWithMeta   = (*SimpleRemoteEvent[any])(nil)
	_ RemoteReactionRemove     = (*SimpleRemoteEvent[any])(nil)
	_ RemoteMessageRemove      = (*SimpleRemoteEvent[any])(nil)
	_ RemoteChatInfoChange     = (*SimpleRemoteEvent[any])(nil)
	_ RemoteChatResyncWithInfo = (*SimpleRemoteEvent[any])(nil)
	_ RemoteChatResyncBackfill = (*SimpleRemoteEvent[any])(nil)
	_ RemoteBackfill           = (*SimpleRemoteEvent[any])(nil)
)

func (sre *SimpleRemoteEvent[T]) AddLogContext(c zerolog.Context) zerolog.Context {
	return sre.LogContext(c)
}

func (sre *SimpleRemoteEvent[T]) GetPortalKey() networkid.PortalKey {
	return sre.PortalKey
}

func (sre *SimpleRemoteEvent[T]) GetTimestamp() time.Time {
	if sre.Timestamp.IsZero() {
		return time.Now()
	}
	return sre.Timestamp
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

func (sre *SimpleRemoteEvent[T]) GetReactionDBMetadata() any {
	return sre.ReactionDBMeta
}

func (sre *SimpleRemoteEvent[T]) GetChatInfoChange(ctx context.Context) (*ChatInfoChange, error) {
	return sre.ChatInfoChange, nil
}

func (sre *SimpleRemoteEvent[T]) GetType() RemoteEventType {
	return sre.Type
}

func (sre *SimpleRemoteEvent[T]) ShouldCreatePortal() bool {
	return sre.CreatePortal
}

func (sre *SimpleRemoteEvent[T]) GetBackfillData(ctx context.Context, portal *Portal) (*FetchMessagesResponse, error) {
	return sre.BackfillData, nil
}

func (sre *SimpleRemoteEvent[T]) CheckNeedsBackfill(ctx context.Context, latestMessage *database.Message) (bool, error) {
	return sre.ResyncBackfillNeeded, nil
}

func (sre *SimpleRemoteEvent[T]) GetChatInfo(ctx context.Context, portal *Portal) (*ChatInfo, error) {
	return sre.ResyncChatInfo, nil
}
