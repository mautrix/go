// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"context"

	"maunium.net/go/mautrix/event"
)

type ToDeviceInterceptor func(context.Context, *event.Event) bool

// RunToDeviceInterceptors calls each interceptor in order and returns true if any interceptor handled the event.
func RunToDeviceInterceptors(ctx context.Context, interceptors []ToDeviceInterceptor, evt *event.Event) bool {
	for _, interceptor := range interceptors {
		if interceptor != nil && interceptor(ctx, evt) {
			return true
		}
	}
	return false
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
	interceptors := cli.toDeviceInterceptors
	cli.toDeviceInterceptorsLock.RUnlock()
	return RunToDeviceInterceptors(ctx, interceptors, evt)
}
