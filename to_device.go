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

// ToDevicePreprocessor can consume or rewrite a to-device event before normal dispatch.
type ToDevicePreprocessor func(context.Context, *event.Event) (handled, keep bool)

func preprocessToDeviceEvent(ctx context.Context, preprocessor ToDevicePreprocessor, evt *event.Event) (handled, keep bool) {
	handled, keep, _ = PreprocessToDeviceEventWithError(ctx, preprocessor, evt)
	return handled, keep
}

// PreprocessToDeviceEventWithError prepares a to-device event and runs an optional preprocessor.
func PreprocessToDeviceEventWithError(ctx context.Context, preprocessor ToDevicePreprocessor, evt *event.Event) (handled, keep bool, err error) {
	err = prepareToDeviceEvent(evt)
	if err != nil {
		if errors.Is(err, event.ErrUnsupportedContentType) {
			return false, true, err
		}
		return false, false, err
	}
	if preprocessor == nil {
		return false, true, nil
	}
	handled, keep = preprocessor(ctx, evt)
	return handled, keep, nil
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
func FilterSyncToDeviceEvents(ctx context.Context, events []*event.Event, preprocessor ToDevicePreprocessor) []*event.Event {
	if len(events) == 0 || preprocessor == nil {
		return events
	}
	filtered := events[:0]
	for _, evt := range events {
		if evt == nil {
			continue
		}
		handled, keep := preprocessToDeviceEvent(ctx, preprocessor, evt)
		if !keep || handled {
			continue
		}
		// Reset Parsed so sync dispatch can parse the event normally.
		evt.Content.Parsed = nil
		filtered = append(filtered, evt)
	}
	return filtered
}

func (cli *Client) HandleToDeviceEvent(ctx context.Context, evt *event.Event) bool {
	if cli == nil || evt == nil {
		return false
	}
	handled, _ := cli.PreDispatchToDeviceEvent(ctx, evt)
	return handled
}

func (cli *Client) PreDispatchToDeviceEvent(ctx context.Context, evt *event.Event) (handled, keep bool) {
	return preprocessToDeviceEvent(ctx, cli.handleBeeperStreamToDeviceEvent, evt)
}

func (cli *Client) handleBeeperStreamToDeviceEvent(ctx context.Context, evt *event.Event) (handled, keep bool) {
	if cli == nil || evt == nil {
		return false, true
	}
	cli.beeperStreamLock.Lock()
	manager := cli.beeperStream
	cli.beeperStreamLock.Unlock()
	if manager == nil {
		return false, true
	}
	handled = manager.handleToDeviceEvent(ctx, evt)
	return handled, true
}
