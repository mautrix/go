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

// EventMeta is a struct containing metadata fields used by most event types.
type EventMeta struct {
	Type         bridgev2.RemoteEventType
	LogContext   func(c zerolog.Context) zerolog.Context
	PortalKey    networkid.PortalKey
	Sender       bridgev2.EventSender
	CreatePortal bool
	Timestamp    time.Time
}

var (
	_ bridgev2.RemoteEvent                    = (*EventMeta)(nil)
	_ bridgev2.RemoteEventThatMayCreatePortal = (*EventMeta)(nil)
	_ bridgev2.RemoteEventWithTimestamp       = (*EventMeta)(nil)
)

func (evt *EventMeta) AddLogContext(c zerolog.Context) zerolog.Context {
	return evt.LogContext(c)
}

func (evt *EventMeta) GetPortalKey() networkid.PortalKey {
	return evt.PortalKey
}

func (evt *EventMeta) GetTimestamp() time.Time {
	if evt.Timestamp.IsZero() {
		return time.Now()
	}
	return evt.Timestamp
}

func (evt *EventMeta) GetSender() bridgev2.EventSender {
	return evt.Sender
}

func (evt *EventMeta) GetType() bridgev2.RemoteEventType {
	return evt.Type
}

func (evt *EventMeta) ShouldCreatePortal() bool {
	return evt.CreatePortal
}

// Message is a simple implementation of [bridgev2.RemoteMessage] and [bridgev2.RemoteEdit].
type Message[T any] struct {
	EventMeta
	Data T

	ID            networkid.MessageID
	TargetMessage networkid.MessageID

	ConvertMessageFunc func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data T) (*bridgev2.ConvertedMessage, error)
	ConvertEditFunc    func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message, data T) (*bridgev2.ConvertedEdit, error)
}

var (
	_ bridgev2.RemoteMessage = (*Message[any])(nil)
	_ bridgev2.RemoteEdit    = (*Message[any])(nil)
)

func (evt *Message[T]) ConvertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI) (*bridgev2.ConvertedMessage, error) {
	return evt.ConvertMessageFunc(ctx, portal, intent, evt.Data)
}

func (evt *Message[T]) ConvertEdit(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message) (*bridgev2.ConvertedEdit, error) {
	return evt.ConvertEditFunc(ctx, portal, intent, existing, evt.Data)
}

func (evt *Message[T]) GetID() networkid.MessageID {
	return evt.ID
}

func (evt *Message[T]) GetTargetMessage() networkid.MessageID {
	return evt.TargetMessage
}

// Reaction is a simple implementation of [bridgev2.RemoteReaction] and [bridgev2.RemoteReactionRemove].
type Reaction struct {
	EventMeta
	TargetMessage  networkid.MessageID
	EmojiID        networkid.EmojiID
	Emoji          string
	ReactionDBMeta any
}

var (
	_ bridgev2.RemoteReaction         = (*Reaction)(nil)
	_ bridgev2.RemoteReactionWithMeta = (*Reaction)(nil)
	_ bridgev2.RemoteReactionRemove   = (*Reaction)(nil)
)

func (evt *Reaction) GetTargetMessage() networkid.MessageID {
	return evt.TargetMessage
}

func (evt *Reaction) GetReactionEmoji() (string, networkid.EmojiID) {
	return evt.Emoji, evt.EmojiID
}

func (evt *Reaction) GetRemovedEmojiID() networkid.EmojiID {
	return evt.EmojiID
}

func (evt *Reaction) GetReactionDBMetadata() any {
	return evt.ReactionDBMeta
}

// ChatResync is a simple implementation of [bridgev2.RemoteChatResync].
//
// If GetChatInfoFunc is set, it will be used to get the chat info. Otherwise, ChatInfo will be used.
//
// If CheckNeedsBackfillFunc is set, it will be used to determine if backfill is required.
// Otherwise, the latest database message timestamp is compared to LatestMessageTS.
//
// All four fields are optional.
type ChatResync struct {
	EventMeta

	ChatInfo        *bridgev2.ChatInfo
	GetChatInfoFunc func(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error)

	LatestMessageTS        time.Time
	CheckNeedsBackfillFunc func(ctx context.Context, latestMessage *database.Message) (bool, error)
}

var (
	_ bridgev2.RemoteChatResync         = (*ChatResync)(nil)
	_ bridgev2.RemoteChatResyncWithInfo = (*ChatResync)(nil)
	_ bridgev2.RemoteChatResyncBackfill = (*ChatResync)(nil)
)

func (evt *ChatResync) CheckNeedsBackfill(ctx context.Context, latestMessage *database.Message) (bool, error) {
	if evt.CheckNeedsBackfillFunc != nil {
		return evt.CheckNeedsBackfillFunc(ctx, latestMessage)
	} else if latestMessage == nil {
		return !evt.LatestMessageTS.IsZero(), nil
	} else {
		return !evt.LatestMessageTS.IsZero() && evt.LatestMessageTS.Before(latestMessage.Timestamp), nil
	}
}

func (evt *ChatResync) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	if evt.GetChatInfoFunc != nil {
		return evt.GetChatInfoFunc(ctx, portal)
	}
	return evt.ChatInfo, nil
}

// ChatDelete is a simple implementation of [bridgev2.RemoteChatDelete].
type ChatDelete struct {
	EventMeta
	OnlyForMe bool
}

var _ bridgev2.RemoteChatDelete = (*ChatDelete)(nil)

func (evt *ChatDelete) DeleteOnlyForMe() bool {
	return evt.OnlyForMe
}

// ChatInfoChange is a simple implementation of [bridgev2.RemoteChatInfoChange].
type ChatInfoChange struct {
	EventMeta

	ChatInfoChange *bridgev2.ChatInfoChange
}

var _ bridgev2.RemoteChatInfoChange = (*ChatInfoChange)(nil)

func (evt *ChatInfoChange) GetChatInfoChange(ctx context.Context) (*bridgev2.ChatInfoChange, error) {
	return evt.ChatInfoChange, nil
}
