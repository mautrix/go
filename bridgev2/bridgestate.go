// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"math/rand/v2"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exfmt"

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

	firstTransientDisconnect time.Time
	cancelScheduledNotice    atomic.Pointer[context.CancelFunc]

	stopChan      chan struct{}
	stopReconnect atomic.Pointer[context.CancelFunc]
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
		ch:       make(chan status.BridgeState, 10),
		stopChan: make(chan struct{}),
		bridge:   br,
		login:    login,
	}
	go bsq.loop()
	return bsq
}

func (bsq *BridgeStateQueue) Destroy() {
	close(bsq.stopChan)
	close(bsq.ch)
	bsq.StopUnknownErrorReconnect()
}

func (bsq *BridgeStateQueue) StopUnknownErrorReconnect() {
	if bsq == nil {
		return
	}
	if cancelFn := bsq.stopReconnect.Swap(nil); cancelFn != nil {
		(*cancelFn)()
	}
	if cancelFn := bsq.cancelScheduledNotice.Swap(nil); cancelFn != nil {
		(*cancelFn)()
	}
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

func (bsq *BridgeStateQueue) scheduleNotice(ctx context.Context, triggeredBy status.BridgeState) {
	log := bsq.login.Log.With().Str("action", "transient disconnect notice").Logger()
	ctx = log.WithContext(bsq.bridge.BackgroundCtx)
	if !bsq.waitForTransientDisconnectReconnect(ctx) {
		return
	}
	prevUnsent := bsq.GetPrevUnsent()
	prev := bsq.GetPrev()
	if triggeredBy.Timestamp != prev.Timestamp || len(bsq.ch) > 0 || bsq.errorSent ||
		prevUnsent.StateEvent != status.StateTransientDisconnect || prev.StateEvent != status.StateTransientDisconnect {
		log.Trace().Any("triggered_by", triggeredBy).Msg("Not sending delayed transient disconnect notice")
		return
	}
	log.Debug().Any("triggered_by", triggeredBy).Msg("Sending delayed transient disconnect notice")
	bsq.sendNotice(ctx, triggeredBy, true)
}

func (bsq *BridgeStateQueue) sendNotice(ctx context.Context, state status.BridgeState, isDelayed bool) {
	noticeConfig := bsq.bridge.Config.BridgeStatusNotices
	isError := state.StateEvent == status.StateBadCredentials ||
		state.StateEvent == status.StateUnknownError ||
		state.UserAction == status.UserActionOpenNative ||
		(isDelayed && state.StateEvent == status.StateTransientDisconnect)
	sendNotice := noticeConfig == "all" || (noticeConfig == "errors" &&
		(isError || (bsq.errorSent && state.StateEvent == status.StateConnected)))
	if state.StateEvent != status.StateTransientDisconnect && state.StateEvent != status.StateUnknownError {
		bsq.firstTransientDisconnect = time.Time{}
	}
	if !sendNotice {
		if !bsq.errorSent && !isDelayed && noticeConfig == "errors" && state.StateEvent == status.StateTransientDisconnect {
			if bsq.firstTransientDisconnect.IsZero() {
				bsq.firstTransientDisconnect = time.Now()
			}
			go bsq.scheduleNotice(ctx, state)
		}
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
	if isDelayed {
		message += fmt.Sprintf(" not resolved after waiting %s", exfmt.Duration(TransientDisconnectNoticeDelay))
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

func (bsq *BridgeStateQueue) unknownErrorReconnect(triggeredBy status.BridgeState) {
	log := bsq.login.Log.With().Str("action", "unknown error reconnect").Logger()
	ctx := log.WithContext(bsq.bridge.BackgroundCtx)
	if !bsq.waitForUnknownErrorReconnect(ctx) {
		return
	}
	prevUnsent := bsq.GetPrevUnsent()
	prev := bsq.GetPrev()
	if triggeredBy.Timestamp != prev.Timestamp {
		log.Debug().Msg("Not reconnecting as a new bridge state was sent after the unknown error")
		return
	} else if len(bsq.ch) > 0 {
		log.Warn().Msg("Not reconnecting as there are unsent bridge states")
		return
	} else if prevUnsent.StateEvent != status.StateUnknownError || prev.StateEvent != status.StateUnknownError {
		log.Debug().Msg("Not reconnecting as the previous state was not an unknown error")
		return
	}
	log.Info().Msg("Disconnecting and reconnecting login due to unknown error")
	bsq.login.Disconnect()
	log.Debug().Msg("Disconnection finished, recreating client and reconnecting")
	err := bsq.login.recreateClient(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to recreate client after unknown error")
		return
	}
	bsq.login.Client.Connect(ctx)
	log.Debug().Msg("Reconnection finished")
}

func (bsq *BridgeStateQueue) waitForUnknownErrorReconnect(ctx context.Context) bool {
	reconnectIn := bsq.bridge.Config.UnknownErrorAutoReconnect
	// Don't allow too low values
	if reconnectIn < 1*time.Minute {
		return false
	}
	reconnectIn += time.Duration(rand.Int64N(int64(float64(reconnectIn)*0.4)) - int64(float64(reconnectIn)*0.2))
	return bsq.waitForReconnect(ctx, reconnectIn, &bsq.stopReconnect)
}

const TransientDisconnectNoticeDelay = 3 * time.Minute

func (bsq *BridgeStateQueue) waitForTransientDisconnectReconnect(ctx context.Context) bool {
	timeUntilSchedule := time.Until(bsq.firstTransientDisconnect.Add(TransientDisconnectNoticeDelay))
	zerolog.Ctx(ctx).Trace().
		Stringer("duration", timeUntilSchedule).
		Msg("Waiting before sending notice about transient disconnect")
	return bsq.waitForReconnect(ctx, timeUntilSchedule, &bsq.cancelScheduledNotice)
}

func (bsq *BridgeStateQueue) waitForReconnect(
	ctx context.Context, reconnectIn time.Duration, ptr *atomic.Pointer[context.CancelFunc],
) bool {
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if oldCancel := ptr.Swap(&cancel); oldCancel != nil {
		(*oldCancel)()
	}
	select {
	case <-time.After(reconnectIn):
		return ptr.CompareAndSwap(&cancel, nil)
	case <-cancelCtx.Done():
		return false
	case <-bsq.stopChan:
		return false
	}
}

func (bsq *BridgeStateQueue) immediateSendBridgeState(state status.BridgeState) {
	if bsq.prevSent != nil && bsq.prevSent.ShouldDeduplicate(&state) {
		bsq.login.Log.Debug().
			Str("state_event", string(state.StateEvent)).
			Msg("Not sending bridge state as it's a duplicate")
		return
	}
	if state.StateEvent == status.StateUnknownError {
		go bsq.unknownErrorReconnect(state)
	}

	ctx := bsq.login.Log.WithContext(context.Background())
	bsq.sendNotice(ctx, state, false)

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
