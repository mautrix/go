// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build js

package appservice

import (
	"context"
	"errors"
	"net/http"

	"github.com/coder/websocket"
)

// ErrWebsocketUnsupported is returned by StartWebsocket in browser builds, where a websocket can't
// carry the appservice token in a header.
var ErrWebsocketUnsupported = errors.New("appservice websockets aren't supported in browser builds")

func (as *AppService) dialWebsocket(ctx context.Context, url string) (*websocket.Conn, *http.Response, error) {
	return nil, nil, ErrWebsocketUnsupported
}
