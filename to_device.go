// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"context"
	"time"

	"maunium.net/go/mautrix/event"
)

type ToDeviceInterceptor func(context.Context, *event.Event) bool

// RunToDeviceInterceptors calls each interceptor in order and returns true if any interceptor handled the event.
func RunToDeviceInterceptors(ctx context.Context, interceptors []ToDeviceInterceptor, evt *event.Event) bool {
	for _, interceptor := range interceptors {
		if ShouldInterceptToDeviceEvent(ctx, interceptor, evt) {
			return true
		}
	}
	return false
}

// ShouldInterceptToDeviceEvent returns true when interceptor handles the event.
func ShouldInterceptToDeviceEvent(ctx context.Context, interceptor ToDeviceInterceptor, evt *event.Event) bool {
	if interceptor == nil || evt == nil {
		return false
	}
	if evt.Content.Parsed == nil {
		_ = evt.Content.ParseRaw(evt.Type)
	}
	return interceptor(ctx, evt)
}

// FilterSyncToDeviceEvents applies interceptor handling for to-device /sync payloads.
//
// It sets the same source metadata that normal sync dispatch would set before invoking
// the interceptor, and keeps only unconsumed events for downstream handling.
func FilterSyncToDeviceEvents(ctx context.Context, events []*event.Event, interceptor ToDeviceInterceptor) []*event.Event {
	if len(events) == 0 || interceptor == nil {
		return events
	}
	filtered := events[:0]
	for _, evt := range events {
		if evt == nil {
			continue
		}
		evt.Type.Class = event.ToDeviceEventType
		evt.Mautrix.EventSource = event.SourceToDevice
		evt.Mautrix.ReceivedAt = time.Now()
		if ShouldInterceptToDeviceEvent(ctx, interceptor, evt) {
			continue
		}
		// Reset Parsed so sync dispatch can parse the event normally.
		evt.Content.Parsed = nil
		filtered = append(filtered, evt)
	}
	return filtered
}

func (cli *Client) AddToDeviceInterceptor(interceptor ToDeviceInterceptor) {
	if cli == nil || interceptor == nil {
		return
	}
	cli.toDeviceInterceptorsLock.Lock()
	defer cli.toDeviceInterceptorsLock.Unlock()
	cli.toDeviceInterceptors = append(cli.toDeviceInterceptors, interceptor)
}

func (cli *Client) HandleToDeviceEvent(ctx context.Context, evt *event.Event) bool {
	if cli == nil || evt == nil {
		return false
	}
	cli.toDeviceInterceptorsLock.RLock()
	interceptors := make([]ToDeviceInterceptor, len(cli.toDeviceInterceptors))
	copy(interceptors, cli.toDeviceInterceptors)
	cli.toDeviceInterceptorsLock.RUnlock()
	return RunToDeviceInterceptors(ctx, interceptors, evt)
}
