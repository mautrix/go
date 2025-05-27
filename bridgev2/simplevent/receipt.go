// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package simplevent

import (
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

type Receipt struct {
	EventMeta

	LastTarget networkid.MessageID
	Targets    []networkid.MessageID
	ReadUpTo   time.Time

	ReadUpToStreamOrder int64
}

var (
	_ bridgev2.RemoteReadReceipt     = (*Receipt)(nil)
	_ bridgev2.RemoteDeliveryReceipt = (*Receipt)(nil)
)

func (evt *Receipt) GetLastReceiptTarget() networkid.MessageID {
	return evt.LastTarget
}

func (evt *Receipt) GetReceiptTargets() []networkid.MessageID {
	return evt.Targets
}

func (evt *Receipt) GetReadUpTo() time.Time {
	return evt.ReadUpTo
}

func (evt *Receipt) GetReadUpToStreamOrder() int64 {
	return evt.ReadUpToStreamOrder
}

type MarkUnread struct {
	EventMeta
	Unread bool
}

var (
	_ bridgev2.RemoteMarkUnread = (*MarkUnread)(nil)
)

func (evt *MarkUnread) GetUnread() bool {
	return evt.Unread
}

type Typing struct {
	EventMeta
	Timeout time.Duration
	Type    bridgev2.TypingType
}

var (
	_ bridgev2.RemoteTyping         = (*Typing)(nil)
	_ bridgev2.RemoteTypingWithType = (*Typing)(nil)
)

func (evt *Typing) GetTimeout() time.Duration {
	return evt.Timeout
}

func (evt *Typing) GetTypingType() bridgev2.TypingType {
	return evt.Type
}
