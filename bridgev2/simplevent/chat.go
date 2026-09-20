// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package simplevent

import (
	"context"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

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
	BundledBackfillData    any
}

var (
	_ bridgev2.RemoteChatResync               = (*ChatResync)(nil)
	_ bridgev2.RemoteChatResyncWithInfo       = (*ChatResync)(nil)
	_ bridgev2.RemoteChatResyncBackfill       = (*ChatResync)(nil)
	_ bridgev2.RemoteChatResyncBackfillBundle = (*ChatResync)(nil)
)

func (evt *ChatResync) CheckNeedsBackfill(ctx context.Context, latestMessage *database.Message) (bool, error) {
	if evt.CheckNeedsBackfillFunc != nil {
		return evt.CheckNeedsBackfillFunc(ctx, latestMessage)
	} else if latestMessage == nil {
		return !evt.LatestMessageTS.IsZero(), nil
	} else {
		return evt.LatestMessageTS.After(latestMessage.Timestamp), nil
	}
}

func (evt *ChatResync) GetBundledBackfillData() any {
	return evt.BundledBackfillData
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
	Children  bool
}

var _ bridgev2.RemoteChatDeleteWithChildren = (*ChatDelete)(nil)

func (evt *ChatDelete) DeleteOnlyForMe() bool {
	return evt.OnlyForMe
}

func (evt *ChatDelete) DeleteChildren() bool {
	return evt.Children
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

// Backfill is a simple implementation of [bridgev2.RemoteBackfill].
type Backfill struct {
	EventMeta
	Data        *bridgev2.FetchMessagesResponse
	GetDataFunc func(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.FetchMessagesResponse, error)
}

var _ bridgev2.RemoteBackfill = (*Backfill)(nil)

func (evt *Backfill) GetBackfillData(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.FetchMessagesResponse, error) {
	if evt.GetDataFunc != nil {
		return evt.GetDataFunc(ctx, portal)
	}
	return evt.Data, nil
}

// PinnedMessages is a simple implementation of [bridgev2.RemotePinnedMessages] and
// [bridgev2.RemotePinnedMessagesDelta].
//
// If Pinned or Unpinned is set, the event is treated as a delta, i.e. the message IDs are
// applied on top of the current pinned list. Otherwise PinnedList is used as the full new list
// of pinned messages.
type PinnedMessages struct {
	EventMeta

	// PinnedList is the full new list of pinned message IDs, newest first.
	PinnedList []networkid.MessageID
	// Pinned and Unpinned are the changed message IDs when the network only sends deltas.
	Pinned   []networkid.MessageID
	Unpinned []networkid.MessageID
}

var (
	_ bridgev2.RemotePinnedMessages      = (*PinnedMessages)(nil)
	_ bridgev2.RemotePinnedMessagesDelta = (*PinnedMessages)(nil)
)

// IsPinnedMessagesDelta returns whether the event describes a change rather than the full pinned list.
func (evt *PinnedMessages) IsPinnedMessagesDelta() bool {
	return len(evt.Pinned) > 0 || len(evt.Unpinned) > 0
}

func (evt *PinnedMessages) GetPinnedMessages(ctx context.Context) ([]networkid.MessageID, error) {
	return evt.PinnedList, nil
}

func (evt *PinnedMessages) GetPinnedMessageChanges(ctx context.Context) (pinned, unpinned []networkid.MessageID, err error) {
	return evt.Pinned, evt.Unpinned, nil
}
