// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package simplevent

import (
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
}

var (
	_ bridgev2.RemoteEvent                            = (*EventMeta)(nil)
	_ bridgev2.RemoteEventWithUncertainPortalReceiver = (*EventMeta)(nil)
	_ bridgev2.RemoteEventThatMayCreatePortal         = (*EventMeta)(nil)
	_ bridgev2.RemoteEventWithTimestamp               = (*EventMeta)(nil)
	_ bridgev2.RemoteEventWithStreamOrder             = (*EventMeta)(nil)
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
