// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"time"

	log "maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix/id"
)

type StateEvent string
type StateErrorCode string

type StateErrorMap map[StateErrorCode]string

func (bem StateErrorMap) Update(data StateErrorMap) {
	for key, value := range data {
		bem[key] = value
	}
}

var StateHumanErrors = make(StateErrorMap)

const (
	StateUnconfigured        StateEvent = "UNCONFIGURED"
	StateRunning             StateEvent = "RUNNING"
	StateConnecting          StateEvent = "CONNECTING"
	StateBackfilling         StateEvent = "BACKFILLING"
	StateConnected           StateEvent = "CONNECTED"
	StateTransientDisconnect StateEvent = "TRANSIENT_DISCONNECT"
	StateBadCredentials      StateEvent = "BAD_CREDENTIALS"
	StateUnknownError        StateEvent = "UNKNOWN_ERROR"
	StateLoggedOut           StateEvent = "LOGGED_OUT"
)

type State struct {
	StateEvent StateEvent `json:"state_event"`
	Timestamp  int64      `json:"timestamp"`
	TTL        int        `json:"ttl"`

	Source  string         `json:"source,omitempty"`
	Error   StateErrorCode `json:"error,omitempty"`
	Message string         `json:"message,omitempty"`

	UserID     id.UserID `json:"user_id,omitempty"`
	RemoteID   string    `json:"remote_id,omitempty"`
	RemoteName string    `json:"remote_name,omitempty"`

	Reason string                 `json:"reason,omitempty"`
	Info   map[string]interface{} `json:"info,omitempty"`
}

type GlobalState struct {
	RemoteStates map[string]State `json:"remoteState"`
	BridgeState  State            `json:"bridgeState"`
}

type StateFiller interface {
	GetMXID() id.UserID
	GetRemoteID() string
	GetRemoteName() string
}

func (pong State) Fill(user StateFiller) State {
	if user != nil {
		pong.UserID = user.GetMXID()
		pong.RemoteID = user.GetRemoteID()
		pong.RemoteName = user.GetRemoteName()
	}

	pong.Timestamp = time.Now().Unix()
	pong.Source = "bridge"
	if len(pong.Error) > 0 {
		pong.TTL = 60
		msg, ok := StateHumanErrors[pong.Error]
		if ok {
			pong.Message = msg
		}
	} else {
		pong.TTL = 240
	}
	return pong
}
func (pong *State) shouldDeduplicate(newPong *State) bool {
	if pong == nil || pong.StateEvent != newPong.StateEvent || pong.Error != newPong.Error {
		return false
	}
	return pong.Timestamp+int64(pong.TTL/5) > time.Now().Unix()
}

func (br *Bridge) SendBridgeState(ctx context.Context, state *State) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(&state); err != nil {
		return fmt.Errorf("failed to encode bridge state JSON: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, br.Config.Homeserver.StatusEndpoint, &body)
	if err != nil {
		return fmt.Errorf("failed to prepare request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+br.Config.AppService.ASToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		respBody, _ := io.ReadAll(resp.Body)
		if respBody != nil {
			respBody = bytes.ReplaceAll(respBody, []byte("\n"), []byte("\\n"))
		}
		return fmt.Errorf("unexpected status code %d sending bridge state update: %s", resp.StatusCode, respBody)
	}
	return nil
}

func (br *Bridge) SendGlobalBridgeState(state State) {
	if len(br.Config.Homeserver.StatusEndpoint) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := br.SendBridgeState(ctx, &state); err != nil {
		br.Log.Warnln("Failed to update global bridge state:", err)
	} else {
		br.Log.Debugfln("Sent new global bridge state %+v", state)
	}
}

type BridgeStateQueue struct {
	prev   *State
	ch     chan State
	log    log.Logger
	bridge *Bridge
	user   StateFiller
}

func (br *Bridge) NewBridgeStateQueue(user StateFiller, log log.Logger) *BridgeStateQueue {
	if len(br.Config.Homeserver.StatusEndpoint) == 0 {
		return nil
	}
	bsq := &BridgeStateQueue{
		ch:     make(chan State, 10),
		log:    log,
		bridge: br,
		user:   user,
	}
	go bsq.loop()
	return bsq
}

func (bsq *BridgeStateQueue) loop() {
	defer func() {
		err := recover()
		if err != nil {
			bsq.log.Errorfln("Bridge state loop panicked: %v\n%s", err, debug.Stack())
		}
	}()
	for state := range bsq.ch {
		bsq.immediateSendBridgeState(state)
	}
}

func (bsq *BridgeStateQueue) immediateSendBridgeState(state State) {
	retryIn := 2
	for {
		if bsq.prev != nil && bsq.prev.shouldDeduplicate(&state) {
			bsq.log.Debugfln("Not sending bridge state %s as it's a duplicate", state.StateEvent)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := bsq.bridge.SendBridgeState(ctx, &state)
		cancel()

		if err != nil {
			bsq.log.Warnfln("Failed to update bridge state: %v, retrying in %d seconds", err, retryIn)
			time.Sleep(time.Duration(retryIn) * time.Second)
			retryIn *= 2
			if retryIn > 64 {
				retryIn = 64
			}
		} else {
			bsq.prev = &state
			bsq.log.Debugfln("Sent new bridge state %+v", state)
			return
		}
	}
}

func (bsq *BridgeStateQueue) Send(state State) {
	if bsq == nil {
		return
	}

	state = state.Fill(bsq.user)

	if len(bsq.ch) >= 8 {
		bsq.log.Warnln("Bridge state queue is nearly full, discarding an item")
		select {
		case <-bsq.ch:
		default:
		}
	}
	select {
	case bsq.ch <- state:
	default:
		bsq.log.Errorfln("Bridge state queue is full, dropped new state")
	}
}

func (bsq *BridgeStateQueue) GetPrev() State {
	if bsq != nil && bsq.prev != nil {
		return *bsq.prev
	}
	return State{}
}

func (bsq *BridgeStateQueue) SetPrev(prev State) {
	if bsq != nil {
		bsq.prev = &prev
	}
}
