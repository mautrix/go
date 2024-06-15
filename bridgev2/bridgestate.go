// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridge/status"
)

type BridgeStateQueue struct {
	prev   *status.BridgeState
	ch     chan status.BridgeState
	bridge *Bridge
	user   status.BridgeStateFiller
}

func (br *Bridge) SendGlobalBridgeState(state status.BridgeState) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := br.Matrix.SendBridgeStatus(ctx, &state); err != nil {
			br.Log.Warn().Err(err).Msg("Failed to update global bridge state")
			cancel()
			time.Sleep(5 * time.Second)
			continue
		} else {
			br.Log.Debug().Any("bridge_state", state).Msg("Sent new global bridge state")
			cancel()
			break
		}
	}
}

func (br *Bridge) NewBridgeStateQueue(user status.BridgeStateFiller) *BridgeStateQueue {
	bsq := &BridgeStateQueue{
		ch:     make(chan status.BridgeState, 10),
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
			bsq.bridge.Log.Error().
				Bytes(zerolog.ErrorStackFieldName, debug.Stack()).
				Any(zerolog.ErrorFieldName, err).
				Msg("Panic in bridge state loop")
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
			bsq.bridge.Log.Debug().
				Str("state_event", string(state.StateEvent)).
				Msg("Not sending bridge state as it's a duplicate")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := bsq.bridge.Matrix.SendBridgeStatus(ctx, &state)
		cancel()

		if err != nil {
			bsq.bridge.Log.Warn().Err(err).
				Int("retry_in_seconds", retryIn).
				Msg("Failed to update bridge state")
			time.Sleep(time.Duration(retryIn) * time.Second)
			retryIn *= 2
			if retryIn > 64 {
				retryIn = 64
			}
		} else {
			bsq.prev = &state
			bsq.bridge.Log.Debug().
				Any("bridge_state", state).
				Msg("Sent new bridge state")
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
		bsq.bridge.Log.Warn().Msg("Bridge state queue is nearly full, discarding an item")
		select {
		case <-bsq.ch:
		default:
		}
	}
	select {
	case bsq.ch <- state:
	default:
		bsq.bridge.Log.Error().Msg("Bridge state queue is full, dropped new state")
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
