// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"

	"github.com/gorilla/websocket"

	"maunium.net/go/mautrix/event"
)

type ErrorResponse struct {
	ErrorCode ErrorCode `json:"errcode"`
	Error     string    `json:"error"`
}

type WebsocketMessage struct {
	Status string `json:"status"`
	TxnID  string `json:"txn_id"`
	EventList
}

func (as *AppService) StartWebsocket(baseURL string) error {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	parsed.Path = filepath.Join(parsed.Path, "_matrix/client/unstable/fi.mau.as_sync")
	if parsed.Scheme == "http" {
		parsed.Scheme = "ws"
	} else if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	}
	ws, resp, err := websocket.DefaultDialer.Dial(parsed.String(), http.Header{
		"Authorization": []string{fmt.Sprintf("Bearer %s", as.Registration.AppToken)},
	})
	if resp != nil && resp.StatusCode >= 400 {
		var errResp ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		if err != nil {
			return fmt.Errorf("websocket request returned HTTP %d with non-JSON body", resp.StatusCode)
		} else {
			return fmt.Errorf("websocket request returned %s (HTTP %d): %s", errResp.ErrorCode, resp.StatusCode, errResp.Error)
		}
	} else if err != nil {
		return fmt.Errorf("failed to open websocket: %w", err)
	}
	if as.StopWebsocket != nil {
		as.StopWebsocket()
	}
	closeChan := make(chan struct{})
	closeChanSync := sync.Once{}
	stopFunc := func() {
		closeChanSync.Do(func() {
			close(closeChan)
		})
	}
	as.StopWebsocket = stopFunc
	as.Log.Debugln("Appservice transaction websocket connected")

	go func() {
		defer stopFunc()
		for {
			var msg WebsocketMessage
			err := ws.ReadJSON(&msg)
			if err != nil {
				as.Log.Warnln("Error reading from websocket:", err)
				return
			}
			if as.Registration.EphemeralEvents && msg.EphemeralEvents != nil {
				as.handleEvents(msg.EphemeralEvents, event.EphemeralEventType)
			}
			as.handleEvents(msg.Events, event.UnknownEventType)
		}
	}()

	<-closeChan

	err = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""))
	if err != nil && err != websocket.ErrCloseSent {
		as.Log.Warnln("Error writing close message to websocket:", err)
	}
	err = ws.Close()
	if err != nil {
		as.Log.Warnln("Error closing websocket:", err)
	}
	return nil
}

