// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"context"
	"errors"
	"time"

	"maunium.net/go/mautrix/event"
)

// ToDeviceInterceptor handles a to-device event and returns true if it consumed the event.
type ToDeviceInterceptor func(context.Context, *event.Event) bool

func interceptToDeviceEvent(ctx context.Context, interceptors []ToDeviceInterceptor, evt *event.Event) (handled, keep bool) {
	err := prepareToDeviceEvent(evt)
	if err != nil {
		if errors.Is(err, event.ErrUnsupportedContentType) {
			return false, true
		}
		return false, false
	}
	for _, interceptor := range interceptors {
		if interceptor != nil && interceptor(ctx, evt) {
			return true, true
		}
	}
	return false, true
}

func prepareToDeviceEvent(evt *event.Event) error {
	if evt == nil {
		return nil
	}
	evt.Type.Class = event.ToDeviceEventType
	evt.Mautrix.EventSource = event.SourceToDevice
	if evt.Mautrix.ReceivedAt.IsZero() {
		evt.Mautrix.ReceivedAt = time.Now()
	}
	if evt.Content.Parsed == nil {
		return evt.Content.ParseRaw(evt.Type)
	}
	return nil
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
		handled, keep := interceptToDeviceEvent(ctx, []ToDeviceInterceptor{interceptor}, evt)
		if !keep || handled {
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
	handled, _ := interceptToDeviceEvent(ctx, interceptors, evt)
	return handled
}
