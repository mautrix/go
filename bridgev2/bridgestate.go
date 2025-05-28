// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
)

type BridgeStateQueue struct {
	prevUnsent *status.BridgeState
	prevSent   *status.BridgeState
	errorSent  bool
	ch         chan status.BridgeState
	bridge     *Bridge
	login      *UserLogin
}

func (br *Bridge) SendGlobalBridgeState(state status.BridgeState) {
	state = state.Fill(nil)
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

func (br *Bridge) NewBridgeStateQueue(login *UserLogin) *BridgeStateQueue {
	bsq := &BridgeStateQueue{
		ch:     make(chan status.BridgeState, 10),
		bridge: br,
		login:  login,
	}
	go bsq.loop()
	return bsq
}

func (bsq *BridgeStateQueue) Destroy() {
	close(bsq.ch)
}

func (bsq *BridgeStateQueue) loop() {
	defer func() {
		err := recover()
		if err != nil {
			bsq.login.Log.Error().
				Bytes(zerolog.ErrorStackFieldName, debug.Stack()).
				Any(zerolog.ErrorFieldName, err).
				Msg("Panic in bridge state loop")
		}
	}()
	for state := range bsq.ch {
		bsq.immediateSendBridgeState(state)
	}
}

func (bsq *BridgeStateQueue) sendNotice(ctx context.Context, state status.BridgeState) {
	noticeConfig := bsq.bridge.Config.BridgeStatusNotices
	isError := state.StateEvent == status.StateBadCredentials ||
		state.StateEvent == status.StateUnknownError ||
		state.UserAction == status.UserActionOpenNative
	sendNotice := noticeConfig == "all" || (noticeConfig == "errors" &&
		(isError || (bsq.errorSent && state.StateEvent == status.StateConnected)))
	if !sendNotice {
		return
	}
	managementRoom, err := bsq.login.User.GetManagementRoom(ctx)
	if err != nil {
		bsq.login.Log.Err(err).Msg("Failed to get management room")
		return
	}
	name := bsq.login.RemoteName
	if name == "" {
		name = fmt.Sprintf("`%s`", bsq.login.ID)
	}
	message := fmt.Sprintf("State update for %s: `%s`", name, state.StateEvent)
	if state.Error != "" {
		message += fmt.Sprintf(" (`%s`)", state.Error)
	}
	if state.Message != "" {
		message += fmt.Sprintf(": %s", state.Message)
	}
	content := format.RenderMarkdown(message, true, false)
	if !isError {
		content.MsgType = event.MsgNotice
	}
	_, err = bsq.bridge.Bot.SendMessage(ctx, managementRoom, event.EventMessage, &event.Content{
		Parsed: content,
		Raw: map[string]any{
			"fi.mau.bridge_state": state,
		},
	}, nil)
	if err != nil {
		bsq.login.Log.Err(err).Msg("Failed to send bridge state notice")
	} else {
		bsq.errorSent = isError
	}
}

func (bsq *BridgeStateQueue) immediateSendBridgeState(state status.BridgeState) {
	if bsq.prevSent != nil && bsq.prevSent.ShouldDeduplicate(&state) {
		bsq.login.Log.Debug().
			Str("state_event", string(state.StateEvent)).
			Msg("Not sending bridge state as it's a duplicate")
		return
	}

	ctx := bsq.login.Log.WithContext(context.Background())
	bsq.sendNotice(ctx, state)

	retryIn := 2
	for {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := bsq.bridge.Matrix.SendBridgeStatus(ctx, &state)
		cancel()

		if err != nil {
			bsq.login.Log.Warn().Err(err).
				Int("retry_in_seconds", retryIn).
				Msg("Failed to update bridge state")
			time.Sleep(time.Duration(retryIn) * time.Second)
			retryIn *= 2
			if retryIn > 64 {
				retryIn = 64
			}
		} else {
			bsq.prevSent = &state
			bsq.login.Log.Debug().
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

	state = state.Fill(bsq.login)
	bsq.prevUnsent = &state

	if len(bsq.ch) >= 8 {
		bsq.login.Log.Warn().Msg("Bridge state queue is nearly full, discarding an item")
		select {
		case <-bsq.ch:
		default:
		}
	}
	select {
	case bsq.ch <- state:
	default:
		bsq.login.Log.Error().Msg("Bridge state queue is full, dropped new state")
	}
}

func (bsq *BridgeStateQueue) GetPrev() status.BridgeState {
	if bsq != nil && bsq.prevSent != nil {
		return *bsq.prevSent
	}
	return status.BridgeState{}
}

func (bsq *BridgeStateQueue) GetPrevUnsent() status.BridgeState {
	if bsq != nil && bsq.prevSent != nil {
		return *bsq.prevUnsent
	}
	return status.BridgeState{}
}

func (bsq *BridgeStateQueue) SetPrev(prev status.BridgeState) {
	if bsq != nil {
		bsq.prevSent = &prev
	}
}
