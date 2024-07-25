// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package simplevent

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

// SimpleRemoteEventMeta is a struct containing metadata fields used by most event types.
type SimpleRemoteEventMeta struct {
	Type         bridgev2.RemoteEventType
	LogContext   func(c zerolog.Context) zerolog.Context
	PortalKey    networkid.PortalKey
	Sender       bridgev2.EventSender
	CreatePortal bool
	Timestamp    time.Time
}

var (
	_ bridgev2.RemoteEvent                    = (*SimpleRemoteEventMeta)(nil)
	_ bridgev2.RemoteEventThatMayCreatePortal = (*SimpleRemoteEventMeta)(nil)
	_ bridgev2.RemoteEventWithTimestamp       = (*SimpleRemoteEventMeta)(nil)
)

func (evt *SimpleRemoteEventMeta) AddLogContext(c zerolog.Context) zerolog.Context {
	return evt.LogContext(c)
}

func (evt *SimpleRemoteEventMeta) GetPortalKey() networkid.PortalKey {
	return evt.PortalKey
}

func (evt *SimpleRemoteEventMeta) GetTimestamp() time.Time {
	if evt.Timestamp.IsZero() {
		return time.Now()
	}
	return evt.Timestamp
}

func (evt *SimpleRemoteEventMeta) GetSender() bridgev2.EventSender {
	return evt.Sender
}

func (evt *SimpleRemoteEventMeta) GetType() bridgev2.RemoteEventType {
	return evt.Type
}

func (evt *SimpleRemoteEventMeta) ShouldCreatePortal() bool {
	return evt.CreatePortal
}

// SimpleRemoteMessage is a simple implementation of [bridgev2.RemoteMessage] and [bridgev2.RemoteEdit].
type SimpleRemoteMessage[T any] struct {
	SimpleRemoteEventMeta
	Data T

	ID            networkid.MessageID
	TargetMessage networkid.MessageID

	ConvertMessageFunc func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data T) (*bridgev2.ConvertedMessage, error)
	ConvertEditFunc    func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message, data T) (*bridgev2.ConvertedEdit, error)
}

var (
	_ bridgev2.RemoteMessage = (*SimpleRemoteMessage[any])(nil)
	_ bridgev2.RemoteEdit    = (*SimpleRemoteMessage[any])(nil)
)

func (evt *SimpleRemoteMessage[T]) ConvertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI) (*bridgev2.ConvertedMessage, error) {
	return evt.ConvertMessageFunc(ctx, portal, intent, evt.Data)
}

func (evt *SimpleRemoteMessage[T]) ConvertEdit(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message) (*bridgev2.ConvertedEdit, error) {
	return evt.ConvertEditFunc(ctx, portal, intent, existing, evt.Data)
}

func (evt *SimpleRemoteMessage[T]) GetID() networkid.MessageID {
	return evt.ID
}

func (evt *SimpleRemoteMessage[T]) GetTargetMessage() networkid.MessageID {
	return evt.TargetMessage
}

// SimpleRemoteReaction is a simple implementation of [bridgev2.RemoteReaction] and [bridgev2.RemoteReactionRemove].
type SimpleRemoteReaction struct {
	SimpleRemoteEventMeta
	TargetMessage  networkid.MessageID
	EmojiID        networkid.EmojiID
	Emoji          string
	ReactionDBMeta any
}

var (
	_ bridgev2.RemoteReaction         = (*SimpleRemoteReaction)(nil)
	_ bridgev2.RemoteReactionWithMeta = (*SimpleRemoteReaction)(nil)
	_ bridgev2.RemoteReactionRemove   = (*SimpleRemoteReaction)(nil)
)

func (evt *SimpleRemoteReaction) GetTargetMessage() networkid.MessageID {
	return evt.TargetMessage
}

func (evt *SimpleRemoteReaction) GetReactionEmoji() (string, networkid.EmojiID) {
	return evt.Emoji, evt.EmojiID
}

func (evt *SimpleRemoteReaction) GetRemovedEmojiID() networkid.EmojiID {
	return evt.EmojiID
}

func (evt *SimpleRemoteReaction) GetReactionDBMetadata() any {
	return evt.ReactionDBMeta
}

// SimpleRemoteChatResync is a simple implementation of [bridgev2.RemoteChatResync].
//
// If GetChatInfoFunc is set, it will be used to get the chat info. Otherwise, ChatInfo will be used.
//
// If CheckNeedsBackfillFunc is set, it will be used to determine if backfill is required.
// Otherwise, the latest database message timestamp is compared to LatestMessageTS.
//
// All four fields are optional.
type SimpleRemoteChatResync struct {
	SimpleRemoteEventMeta

	ChatInfo        *bridgev2.ChatInfo
	GetChatInfoFunc func(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error)

	LatestMessageTS        time.Time
	CheckNeedsBackfillFunc func(ctx context.Context, latestMessage *database.Message) (bool, error)
}

var (
	_ bridgev2.RemoteChatResync         = (*SimpleRemoteChatResync)(nil)
	_ bridgev2.RemoteChatResyncWithInfo = (*SimpleRemoteChatResync)(nil)
	_ bridgev2.RemoteChatResyncBackfill = (*SimpleRemoteChatResync)(nil)
)

func (evt *SimpleRemoteChatResync) CheckNeedsBackfill(ctx context.Context, latestMessage *database.Message) (bool, error) {
	if evt.CheckNeedsBackfillFunc != nil {
		return evt.CheckNeedsBackfillFunc(ctx, latestMessage)
	} else if latestMessage == nil {
		return !evt.LatestMessageTS.IsZero(), nil
	} else {
		return !evt.LatestMessageTS.IsZero() && evt.LatestMessageTS.Before(latestMessage.Timestamp), nil
	}
}

func (evt *SimpleRemoteChatResync) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	if evt.GetChatInfoFunc != nil {
		return evt.GetChatInfoFunc(ctx, portal)
	}
	return evt.ChatInfo, nil
}

// SimpleRemoteChatDelete is a simple implementation of [bridgev2.RemoteChatDelete].
type SimpleRemoteChatDelete struct {
	SimpleRemoteEventMeta
	OnlyForMe bool
}

var _ bridgev2.RemoteChatDelete = (*SimpleRemoteChatDelete)(nil)

func (evt *SimpleRemoteChatDelete) DeleteOnlyForMe() bool {
	return evt.OnlyForMe
}

// SimpleRemoteChatInfoChange is a simple implementation of [bridgev2.RemoteChatInfoChange].
type SimpleRemoteChatInfoChange struct {
	SimpleRemoteEventMeta

	ChatInfoChange *bridgev2.ChatInfoChange
}

var _ bridgev2.RemoteChatInfoChange = (*SimpleRemoteChatInfoChange)(nil)

func (evt *SimpleRemoteChatInfoChange) GetChatInfoChange(ctx context.Context) (*bridgev2.ChatInfoChange, error) {
	return evt.ChatInfoChange, nil
}
