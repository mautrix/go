// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"maunium.net/go/mautrix"
)

type WebsocketRequest struct {
	ReqID   int    `json:"id,omitempty"`
	Command string `json:"command"`
	Data    any    `json:"data"`
}

type WebsocketCommand struct {
	ReqID   int             `json:"id,omitempty"`
	Command string          `json:"command"`
	Data    json.RawMessage `json:"data"`

	Ctx context.Context `json:"-"`
}

func (wsc *WebsocketCommand) MakeResponse(ok bool, data any) *WebsocketRequest {
	if wsc.ReqID == 0 || wsc.Command == "response" || wsc.Command == "error" {
		return nil
	}
	cmd := "response"
	if !ok {
		cmd = "error"
	}
	if err, isError := data.(error); isError {
		var errorData json.RawMessage
		var jsonErr error
		unwrappedErr := err
		var prefixMessage string
		for unwrappedErr != nil {
			errorData, jsonErr = json.Marshal(unwrappedErr)
			if errorData != nil && len(errorData) > 2 && jsonErr == nil {
				prefixMessage = strings.Replace(err.Error(), unwrappedErr.Error(), "", 1)
				prefixMessage = strings.TrimRight(prefixMessage, ": ")
				break
			}
			unwrappedErr = errors.Unwrap(unwrappedErr)
		}
		if errorData != nil {
			if !gjson.GetBytes(errorData, "message").Exists() {
				errorData, _ = sjson.SetBytes(errorData, "message", err.Error())
			} // else: marshaled error contains a message already
		} else {
			errorData, _ = sjson.SetBytes(nil, "message", err.Error())
		}
		if len(prefixMessage) > 0 {
			errorData, _ = sjson.SetBytes(errorData, "prefix_message", prefixMessage)
		}
		data = errorData
	}
	return &WebsocketRequest{
		ReqID:   wsc.ReqID,
		Command: cmd,
		Data:    data,
	}
}

type WebsocketTransaction struct {
	Status string `json:"status"`
	TxnID  string `json:"txn_id"`
	Transaction
}

type WebsocketTransactionResponse struct {
	TxnID string `json:"txn_id"`
}

type WebsocketMessage struct {
	WebsocketTransaction
	WebsocketCommand
}

const (
	WebsocketCloseConnReplaced       websocket.StatusCode = 4001
	WebsocketCloseTxnNotAcknowledged websocket.StatusCode = 4002
)

type MeowWebsocketCloseCode string

const (
	MeowServerShuttingDown MeowWebsocketCloseCode = "server_shutting_down"
	MeowConnectionReplaced MeowWebsocketCloseCode = "conn_replaced"
	MeowTxnNotAcknowledged MeowWebsocketCloseCode = "transactions_not_acknowledged"
)

var (
	ErrWebsocketManualStop   = errors.New("the websocket was disconnected manually")
	ErrWebsocketOverridden   = errors.New("a new call to StartWebsocket overrode the previous connection")
	ErrWebsocketUnknownError = errors.New("an unknown error occurred")

	ErrWebsocketNotConnected = errors.New("websocket not connected")
	ErrWebsocketClosed       = errors.New("websocket closed before response received")
)

func (mwcc MeowWebsocketCloseCode) String() string {
	switch mwcc {
	case MeowServerShuttingDown:
		return "the server is shutting down"
	case MeowConnectionReplaced:
		return "the connection was replaced by another client"
	case MeowTxnNotAcknowledged:
		return "transactions were not acknowledged"
	default:
		return string(mwcc)
	}
}

type CloseCommand struct {
	Code    websocket.StatusCode   `json:"-"`
	Command string                 `json:"command"`
	Status  MeowWebsocketCloseCode `json:"status"`
}

func (cc CloseCommand) Error() string {
	return fmt.Sprintf("websocket: close %d: %s", cc.Code, cc.Status.String())
}

func parseCloseError(err error) error {
	var closeError websocket.CloseError
	if !errors.As(err, &closeError) {
		return err
	}
	var closeCommand CloseCommand
	closeCommand.Code = closeError.Code
	closeCommand.Command = "disconnect"
	if len(closeError.Reason) > 0 {
		jsonErr := json.Unmarshal([]byte(closeError.Reason), &closeCommand)
		if jsonErr != nil {
			return err
		}
	}
	if len(closeCommand.Status) == 0 {
		if closeCommand.Code == WebsocketCloseConnReplaced {
			closeCommand.Status = MeowConnectionReplaced
		} else if closeCommand.Code == websocket.StatusServiceRestart {
			closeCommand.Status = MeowServerShuttingDown
		}
	}
	return &closeCommand
}

func (as *AppService) HasWebsocket() bool {
	return as.ws != nil
}

func (as *AppService) SendWebsocket(ctx context.Context, cmd *WebsocketRequest) error {
	ws := as.ws
	if cmd == nil {
		return nil
	} else if ws == nil {
		return ErrWebsocketNotConnected
	}
	wr, err := ws.Writer(ctx, websocket.MessageText)
	if err != nil {
		return err
	}
	err = json.NewEncoder(wr).Encode(cmd)
	if err != nil {
		return err
	}
	return nil
}

func (as *AppService) clearWebsocketResponseWaiters() {
	as.websocketRequestsLock.Lock()
	for _, waiter := range as.websocketRequests {
		waiter <- &WebsocketCommand{Command: "__websocket_closed"}
	}
	as.websocketRequests = make(map[int]chan<- *WebsocketCommand)
	as.websocketRequestsLock.Unlock()
}

func (as *AppService) addWebsocketResponseWaiter(reqID int, waiter chan<- *WebsocketCommand) {
	as.websocketRequestsLock.Lock()
	as.websocketRequests[reqID] = waiter
	as.websocketRequestsLock.Unlock()
}

func (as *AppService) removeWebsocketResponseWaiter(reqID int, waiter chan<- *WebsocketCommand) {
	as.websocketRequestsLock.Lock()
	existingWaiter, ok := as.websocketRequests[reqID]
	if ok && existingWaiter == waiter {
		delete(as.websocketRequests, reqID)
	}
	close(waiter)
	as.websocketRequestsLock.Unlock()
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (er *ErrorResponse) Error() string {
	return fmt.Sprintf("%s: %s", er.Code, er.Message)
}

func (as *AppService) RequestWebsocket(ctx context.Context, cmd *WebsocketRequest, response any) error {
	cmd.ReqID = int(atomic.AddInt32(&as.websocketRequestID, 1))
	respChan := make(chan *WebsocketCommand, 1)
	as.addWebsocketResponseWaiter(cmd.ReqID, respChan)
	defer as.removeWebsocketResponseWaiter(cmd.ReqID, respChan)
	err := as.SendWebsocket(ctx, cmd)
	if err != nil {
		return err
	}
	select {
	case resp := <-respChan:
		if resp.Command == "__websocket_closed" {
			return ErrWebsocketClosed
		} else if resp.Command == "error" {
			var respErr ErrorResponse
			err = json.Unmarshal(resp.Data, &respErr)
			if err != nil {
				return fmt.Errorf("failed to parse error JSON: %w", err)
			}
			return &respErr
		} else if response != nil {
			err = json.Unmarshal(resp.Data, &response)
			if err != nil {
				return fmt.Errorf("failed to parse response JSON: %w", err)
			}
			return nil
		} else {
			return nil
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (as *AppService) unknownCommandHandler(cmd WebsocketCommand) (bool, any) {
	zerolog.Ctx(cmd.Ctx).Warn().Msg("No handler for websocket command")
	return false, fmt.Errorf("unknown request type")
}

func (as *AppService) SetWebsocketCommandHandler(cmd string, handler WebsocketHandler) {
	as.websocketHandlersLock.Lock()
	as.websocketHandlers[cmd] = handler
	as.websocketHandlersLock.Unlock()
}

type WebsocketTransactionHandler func(ctx context.Context, msg WebsocketMessage) (bool, any)

func (as *AppService) defaultHandleWebsocketTransaction(ctx context.Context, msg WebsocketMessage) (bool, any) {
	if msg.TxnID == "" || !as.txnIDC.IsProcessed(msg.TxnID) {
		as.handleTransaction(ctx, msg.TxnID, &msg.Transaction)
	} else {
		zerolog.Ctx(ctx).Debug().
			Object("content", &msg.Transaction).
			Msg("Ignoring duplicate transaction")
	}
	return true, &WebsocketTransactionResponse{TxnID: msg.TxnID}
}

func (as *AppService) consumeWebsocket(ctx context.Context, stopFunc func(error), ws *websocket.Conn) {
	defer stopFunc(ErrWebsocketUnknownError)
	for {
		msgType, reader, err := ws.Reader(ctx)
		if err != nil {
			as.Log.Debug().Err(err).Msg("Error getting reader from websocket")
			stopFunc(parseCloseError(err))
			return
		} else if msgType != websocket.MessageText {
			as.Log.Debug().Msg("Ignoring non-text message from websocket")
			continue
		}
		var msg WebsocketMessage
		err = json.NewDecoder(reader).Decode(&msg)
		if err != nil {
			as.Log.Debug().Err(err).Msg("Error reading JSON from websocket")
			stopFunc(parseCloseError(err))
			return
		}
		with := as.Log.With().
			Int("req_id", msg.ReqID).
			Str("ws_command", msg.Command)
		if msg.TxnID != "" {
			with = with.Str("transaction_id", msg.TxnID)
		}
		log := with.Logger()
		ctx := log.WithContext(ctx)
		if msg.Command == "" || msg.Command == "transaction" {
			ok, resp := as.WebsocketTransactionHandler(ctx, msg)
			go func() {
				err := as.SendWebsocket(ctx, msg.MakeResponse(ok, resp))
				if err != nil {
					log.Warn().Err(err).Msg("Failed to send response to websocket transaction")
				} else {
					log.Debug().Msg("Sent response to transaction")
				}
			}()
		} else if msg.Command == "connect" {
			log.Debug().Msg("Websocket connect confirmation received")
		} else if msg.Command == "response" || msg.Command == "error" {
			as.websocketRequestsLock.RLock()
			respChan, ok := as.websocketRequests[msg.ReqID]
			if ok {
				select {
				case respChan <- &msg.WebsocketCommand:
				default:
					log.Warn().Msg("Failed to handle response: channel didn't accept response")
				}
			} else {
				log.Warn().Msg("Dropping response to unknown request ID")
			}
			as.websocketRequestsLock.RUnlock()
		} else {
			log.Debug().Msg("Received websocket command")
			as.websocketHandlersLock.RLock()
			handler, ok := as.websocketHandlers[msg.Command]
			as.websocketHandlersLock.RUnlock()
			if !ok {
				handler = as.unknownCommandHandler
			}
			go func() {
				okResp, data := handler(msg.WebsocketCommand)
				err := as.SendWebsocket(ctx, msg.MakeResponse(okResp, data))
				if err != nil {
					log.Error().Err(err).Msg("Failed to send response to websocket command")
				} else if okResp {
					log.Debug().Msg("Sent success response to websocket command")
				} else {
					log.Debug().Msg("Sent error response to websocket command")
				}
			}()
		}
	}
}

func (as *AppService) StartWebsocket(ctx context.Context, baseURL string, onConnect func()) error {
	var parsed *url.URL
	if baseURL != "" {
		var err error
		parsed, err = url.Parse(baseURL)
		if err != nil {
			return fmt.Errorf("failed to parse URL: %w", err)
		}
	} else {
		copiedURL := *as.hsURLForClient
		parsed = &copiedURL
	}
	parsed.Path = filepath.Join(parsed.Path, "_matrix/client/unstable/fi.mau.as_sync")
	if parsed.Scheme == "http" {
		parsed.Scheme = "ws"
	} else if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	}
	ws, resp, err := websocket.Dial(ctx, parsed.String(), &websocket.DialOptions{
		HTTPClient: as.HTTPClient,
		HTTPHeader: http.Header{
			"Authorization": []string{fmt.Sprintf("Bearer %s", as.Registration.AppToken)},
			"User-Agent":    []string{as.BotClient().UserAgent},

			"X-Mautrix-Process-ID":        []string{as.ProcessID},
			"X-Mautrix-Websocket-Version": []string{"3"},
		},
	})
	if resp != nil && resp.StatusCode >= 400 {
		var errResp mautrix.RespError
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		if err != nil {
			return fmt.Errorf("websocket request returned HTTP %d with non-JSON body", resp.StatusCode)
		} else {
			return fmt.Errorf("websocket request returned %s (HTTP %d): %s", errResp.ErrCode, resp.StatusCode, errResp.Err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to open websocket: %w", err)
	}
	if as.StopWebsocket != nil {
		as.StopWebsocket(ErrWebsocketOverridden)
	}
	closeChan := make(chan error)
	closeChanOnce := sync.Once{}
	stopFunc := func(err error) {
		closeChanOnce.Do(func() {
			select {
			case closeChan <- err:
			default:
				as.Log.Warn().
					AnErr("close_error", err).
					Msg("Nothing is reading on close channel")
				closeChan <- err
				as.Log.Warn().Msg("Websocket close completed after being stuck")
			}
		})
	}
	as.ws = ws
	as.StopWebsocket = stopFunc
	as.PrepareWebsocket()
	as.Log.Debug().Msg("Appservice transaction websocket opened")

	go as.consumeWebsocket(ctx, stopFunc, ws)

	var onConnectDone atomic.Bool
	if onConnect != nil {
		go func() {
			onConnect()
			onConnectDone.Store(true)
		}()
	} else {
		onConnectDone.Store(true)
	}

	closeErr := <-closeChan
	if !onConnectDone.Load() {
		as.Log.Warn().Msg("Websocket closed before onConnect returned, things may explode")
	}

	if as.ws == ws {
		as.clearWebsocketResponseWaiters()
		as.ws = nil
	}

	err = ws.Close(websocket.StatusGoingAway, "")
	if err != nil {
		as.Log.Warn().Err(err).Msg("Error closing websocket")
	}
	return closeErr
}
