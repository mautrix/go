// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridge

import (
	"context"
	"runtime/debug"
	"time"

	log "maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix/bridge/status"
)

func (br *Bridge) SendBridgeState(ctx context.Context, state *status.BridgeState) error {
	return state.Send(ctx, br.Config.Homeserver.StatusEndpoint, br.Config.AppService.ASToken)
}

func (br *Bridge) SendGlobalBridgeState(state status.BridgeState) {
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
	prev   *status.BridgeState
	ch     chan status.BridgeState
	log    log.Logger
	bridge *Bridge
	user   status.BridgeStateFiller
}

func (br *Bridge) NewBridgeStateQueue(user status.BridgeStateFiller, log log.Logger) *BridgeStateQueue {
	if len(br.Config.Homeserver.StatusEndpoint) == 0 {
		return nil
	}
	bsq := &BridgeStateQueue{
		ch:     make(chan status.BridgeState, 10),
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

func (bsq *BridgeStateQueue) immediateSendBridgeState(state status.BridgeState) {
	retryIn := 2
	for {
		if bsq.prev != nil && bsq.prev.ShouldDeduplicate(&state) {
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

func (bsq *BridgeStateQueue) Send(state status.BridgeState) {
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

func (bsq *BridgeStateQueue) GetPrev() status.BridgeState {
	if bsq != nil && bsq.prev != nil {
		return *bsq.prev
	}
	return status.BridgeState{}
}

func (bsq *BridgeStateQueue) SetPrev(prev status.BridgeState) {
	if bsq != nil {
		bsq.prev = &prev
	}
}
