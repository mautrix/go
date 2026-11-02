// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !js

package appservice

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coder/websocket"
)

func (as *AppService) dialWebsocket(ctx context.Context, url string) (*websocket.Conn, *http.Response, error) {
	return websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPClient: as.HTTPClient,
		HTTPHeader: http.Header{
			"Authorization": []string{fmt.Sprintf("Bearer %s", as.Registration.AppToken)},
			"User-Agent":    []string{as.UserAgent},

			"X-Mautrix-Process-ID":        []string{as.ProcessID},
			"X-Mautrix-Websocket-Version": []string{"3"},
		},
	})
}
