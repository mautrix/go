// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package simplevent

import (
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

// Reaction is a simple implementation of [bridgev2.RemoteReaction] and [bridgev2.RemoteReactionRemove].
type Reaction struct {
	EventMeta
	TargetMessage  networkid.MessageID
	EmojiID        networkid.EmojiID
	Emoji          string
	ExtraContent   map[string]any
	ReactionDBMeta any
}

var (
	_ bridgev2.RemoteReaction                 = (*Reaction)(nil)
	_ bridgev2.RemoteReactionWithMeta         = (*Reaction)(nil)
	_ bridgev2.RemoteReactionWithExtraContent = (*Reaction)(nil)
	_ bridgev2.RemoteReactionRemove           = (*Reaction)(nil)
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

func (evt *Reaction) GetReactionExtraContent() map[string]any {
	return evt.ExtraContent
}

type ReactionSync struct {
	EventMeta
	TargetMessage networkid.MessageID
	Reactions     *bridgev2.ReactionSyncData
}

var (
	_ bridgev2.RemoteReactionSync = (*ReactionSync)(nil)
)

func (evt *ReactionSync) GetTargetMessage() networkid.MessageID {
	return evt.TargetMessage
}

func (evt *ReactionSync) GetReactions() *bridgev2.ReactionSyncData {
	return evt.Reactions
}
