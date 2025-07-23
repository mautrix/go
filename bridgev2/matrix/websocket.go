// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"maunium.net/go/mautrix/appservice"
)

const defaultReconnectBackoff = 2 * time.Second
const maxReconnectBackoff = 2 * time.Minute
const reconnectBackoffReset = 5 * time.Minute

func (br *Connector) startWebsocket(wg *sync.WaitGroup) {
	log := br.Log.With().Str("action", "appservice websocket").Logger()
	var wgOnce sync.Once
	onConnect := func() {
		if br.hasSentAnyStates {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				for _, state := range br.Bridge.GetCurrentBridgeStates() {
					err := br.SendBridgeStatus(ctx, &state)
					if err != nil {
						log.Err(err).Msg("Failed to resend latest bridge state after websocket reconnect")
					} else {
						log.Debug().Any("bridge_state", state).Msg("Resent bridge state after websocket reconnect")
					}
				}
			}()
		}
		wgOnce.Do(wg.Done)
		select {
		case br.wsStarted <- struct{}{}:
		default:
		}
	}
	reconnectBackoff := defaultReconnectBackoff
	lastDisconnect := time.Now().UnixNano()
	br.wsStopped = make(chan struct{})
	defer func() {
		log.Debug().Msg("Appservice websocket loop finished")
		close(br.wsStopped)
	}()
	addr := br.Config.Homeserver.WSProxy
	if addr == "" {
		addr = br.Config.Homeserver.Address
	}
	for {
		err := br.AS.StartWebsocket(br.Bridge.BackgroundCtx, addr, onConnect)
		if errors.Is(err, appservice.ErrWebsocketManualStop) {
			return
		} else if closeCommand := (&appservice.CloseCommand{}); errors.As(err, &closeCommand) && closeCommand.Status == appservice.MeowConnectionReplaced {
			log.Warn().Msg("Appservice websocket closed by another instance of the bridge, shutting down...")
			if br.OnWebsocketReplaced != nil {
				br.OnWebsocketReplaced()
			} else {
				os.Exit(1)
			}
			return
		} else if err != nil {
			log.Err(err).Msg("Error in appservice websocket")
		}
		if br.stopping {
			return
		}
		now := time.Now().UnixNano()
		if lastDisconnect+reconnectBackoffReset.Nanoseconds() < now {
			reconnectBackoff = defaultReconnectBackoff
		} else {
			reconnectBackoff *= 2
			if reconnectBackoff > maxReconnectBackoff {
				reconnectBackoff = maxReconnectBackoff
			}
		}
		lastDisconnect = now
		log.Info().
			Int("backoff_seconds", int(reconnectBackoff.Seconds())).
			Msg("Websocket disconnected, reconnecting...")
		select {
		case <-br.wsShortCircuitReconnectBackoff:
			log.Debug().Msg("Reconnect backoff was short-circuited")
		case <-time.After(reconnectBackoff):
		}
		if br.stopping {
			return
		}
	}
}

type wsPingData struct {
	Timestamp int64 `json:"timestamp"`
}

func (br *Connector) PingServer() (start, serverTs, end time.Time) {
	if !br.Websocket {
		panic(fmt.Errorf("PingServer called without websocket enabled"))
	}
	if !br.AS.HasWebsocket() {
		br.Log.Debug().Msg("Received server ping request, but no websocket connected. Trying to short-circuit backoff sleep")
		select {
		case br.wsShortCircuitReconnectBackoff <- struct{}{}:
		default:
			br.Log.Warn().Msg("Failed to ping websocket: not connected and no backoff?")
			return
		}
		select {
		case <-br.wsStarted:
		case <-time.After(15 * time.Second):
			if !br.AS.HasWebsocket() {
				br.Log.Warn().Msg("Failed to ping websocket: didn't connect after 15 seconds of waiting")
				return
			}
		}
	}
	start = time.Now()
	var resp wsPingData
	br.Log.Debug().Msg("Pinging appservice websocket")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := br.AS.RequestWebsocket(ctx, &appservice.WebsocketRequest{
		Command: "ping",
		Data:    &wsPingData{Timestamp: start.UnixMilli()},
	}, &resp)
	end = time.Now()
	if err != nil {
		br.Log.Warn().Err(err).Dur("duration", end.Sub(start)).Msg("Websocket ping returned error")
		br.AS.StopWebsocket(fmt.Errorf("websocket ping returned error in %s: %w", end.Sub(start), err))
	} else {
		serverTs = time.Unix(0, resp.Timestamp*int64(time.Millisecond))
		br.Log.Debug().
			Dur("duration", end.Sub(start)).
			Dur("req_duration", serverTs.Sub(start)).
			Dur("resp_duration", end.Sub(serverTs)).
			Msg("Websocket ping returned success")
	}
	return
}

func (br *Connector) websocketServerPinger() {
	interval := time.Duration(br.Config.Homeserver.WSPingInterval) * time.Second
	clock := time.NewTicker(interval)
	defer func() {
		br.Log.Info().Msg("Stopping websocket pinger")
		clock.Stop()
	}()
	br.Log.Info().Dur("interval_duration", interval).Msg("Starting websocket pinger")
	for {
		select {
		case <-clock.C:
			br.PingServer()
		case <-br.wsStopPinger:
			return
		}
		if br.stopping {
			return
		}
	}
}
