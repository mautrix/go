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
	"maunium.net/go/mautrix/bridgev2/networkid"
)

// EventMeta is a struct containing metadata fields used by most event types.
type EventMeta struct {
	Type              bridgev2.RemoteEventType
	LogContext        func(c zerolog.Context) zerolog.Context
	PortalKey         networkid.PortalKey
	UncertainReceiver bool
	Sender            bridgev2.EventSender
	CreatePortal      bool
	Timestamp         time.Time
	StreamOrder       int64

	PreHandleFunc  func(context.Context, *bridgev2.Portal)
	PostHandleFunc func(context.Context, *bridgev2.Portal)
}

var (
	_ bridgev2.RemoteEvent                            = (*EventMeta)(nil)
	_ bridgev2.RemoteEventWithUncertainPortalReceiver = (*EventMeta)(nil)
	_ bridgev2.RemoteEventThatMayCreatePortal         = (*EventMeta)(nil)
	_ bridgev2.RemoteEventWithTimestamp               = (*EventMeta)(nil)
	_ bridgev2.RemoteEventWithStreamOrder             = (*EventMeta)(nil)
	_ bridgev2.RemotePreHandler                       = (*EventMeta)(nil)
	_ bridgev2.RemotePostHandler                      = (*EventMeta)(nil)
)

func (evt *EventMeta) AddLogContext(c zerolog.Context) zerolog.Context {
	if evt.LogContext == nil {
		return c
	}
	return evt.LogContext(c)
}

func (evt *EventMeta) GetPortalKey() networkid.PortalKey {
	return evt.PortalKey
}

func (evt *EventMeta) PortalReceiverIsUncertain() bool {
	return evt.UncertainReceiver
}

func (evt *EventMeta) GetTimestamp() time.Time {
	if evt.Timestamp.IsZero() {
		return time.Now()
	}
	return evt.Timestamp
}

func (evt *EventMeta) GetStreamOrder() int64 {
	return evt.StreamOrder
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

func (evt *EventMeta) PreHandle(ctx context.Context, portal *bridgev2.Portal) {
	if evt.PreHandleFunc != nil {
		evt.PreHandleFunc(ctx, portal)
	}
}

func (evt *EventMeta) PostHandle(ctx context.Context, portal *bridgev2.Portal) {
	if evt.PostHandleFunc != nil {
		evt.PostHandleFunc(ctx, portal)
	}
}

func (evt EventMeta) WithType(t bridgev2.RemoteEventType) EventMeta {
	evt.Type = t
	return evt
}

func (evt EventMeta) WithLogContext(f func(c zerolog.Context) zerolog.Context) EventMeta {
	evt.LogContext = f
	return evt
}

func (evt EventMeta) WithPortalKey(p networkid.PortalKey) EventMeta {
	evt.PortalKey = p
	return evt
}

func (evt EventMeta) WithUncertainReceiver(u bool) EventMeta {
	evt.UncertainReceiver = u
	return evt
}

func (evt EventMeta) WithSender(s bridgev2.EventSender) EventMeta {
	evt.Sender = s
	return evt
}

func (evt EventMeta) WithCreatePortal(c bool) EventMeta {
	evt.CreatePortal = c
	return evt
}

func (evt EventMeta) WithTimestamp(t time.Time) EventMeta {
	evt.Timestamp = t
	return evt
}

func (evt EventMeta) WithStreamOrder(s int64) EventMeta {
	evt.StreamOrder = s
	return evt
}
