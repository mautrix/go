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
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/exstrings"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Start starts the HTTP server that listens for calls from the Matrix homeserver.
func (as *AppService) Start() {
	as.server = &http.Server{
		Handler: as.Router,
	}
	var err error
	if as.Host.IsUnixSocket() {
		err = as.listenUnix()
	} else {
		as.server.Addr = as.Host.Address()
		err = as.listenTCP()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		as.Log.Error().Err(err).Msg("Error in HTTP listener")
	} else {
		as.Log.Debug().Msg("HTTP listener stopped")
	}
}

func (as *AppService) listenUnix() error {
	socket := as.Host.Hostname
	_ = syscall.Unlink(socket)
	defer func() {
		_ = syscall.Unlink(socket)
	}()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	as.Log.Info().Str("socket", socket).Msg("Starting unix socket HTTP listener")
	return as.server.Serve(listener)
}

func (as *AppService) listenTCP() error {
	as.Log.Info().Str("address", as.server.Addr).Msg("Starting HTTP listener")
	return as.server.ListenAndServe()
}

func (as *AppService) Stop() {
	if as.server == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = as.server.Shutdown(ctx)
	as.server = nil
}

// CheckServerToken checks if the given request originated from the Matrix homeserver.
func (as *AppService) CheckServerToken(w http.ResponseWriter, r *http.Request) (isValid bool) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		mautrix.MMissingToken.WithMessage("Missing access token").Write(w)
	} else if !exstrings.ConstantTimeEqual(authHeader[len("Bearer "):], as.Registration.ServerToken) {
		mautrix.MUnknownToken.WithMessage("Invalid access token").Write(w)
	} else {
		isValid = true
	}
	return
}

// PutTransaction handles a /transactions PUT call from the homeserver.
func (as *AppService) PutTransaction(w http.ResponseWriter, r *http.Request) {
	if !as.CheckServerToken(w, r) {
		return
	}

	txnID := r.PathValue("txnID")
	if len(txnID) == 0 {
		mautrix.MInvalidParam.WithMessage("Missing transaction ID").Write(w)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		mautrix.MNotJSON.WithMessage("Failed to read response body").Write(w)
		return
	}
	log := as.Log.With().Str("transaction_id", txnID).Logger()
	// Don't use request context, handling shouldn't be stopped even if the request times out
	ctx := context.Background()
	ctx = log.WithContext(ctx)
	if as.txnIDC.IsProcessed(txnID) {
		// Duplicate transaction ID: no-op
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
		log.Debug().Msg("Ignoring duplicate transaction")
		return
	}

	var txn Transaction
	err = json.Unmarshal(body, &txn)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse transaction content")
		mautrix.MBadJSON.WithMessage("Failed to parse transaction content").Write(w)
	} else {
		as.handleTransaction(ctx, txnID, &txn)
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	}
}

func (as *AppService) handleTransaction(ctx context.Context, id string, txn *Transaction) {
	log := zerolog.Ctx(ctx)
	log.Debug().Object("content", txn).Msg("Starting handling of transaction")
	if as.Registration.EphemeralEvents {
		if txn.EphemeralEvents != nil {
			as.handleEvents(ctx, txn.EphemeralEvents, event.EphemeralEventType)
		} else if txn.MSC2409EphemeralEvents != nil {
			as.handleEvents(ctx, txn.MSC2409EphemeralEvents, event.EphemeralEventType)
		}
		if txn.ToDeviceEvents != nil {
			as.handleEvents(ctx, txn.ToDeviceEvents, event.ToDeviceEventType)
		} else if txn.MSC2409ToDeviceEvents != nil {
			as.handleEvents(ctx, txn.MSC2409ToDeviceEvents, event.ToDeviceEventType)
		}
	}
	as.handleEvents(ctx, txn.Events, event.UnknownEventType)
	if txn.DeviceLists != nil {
		as.handleDeviceLists(ctx, txn.DeviceLists)
	} else if txn.MSC3202DeviceLists != nil {
		as.handleDeviceLists(ctx, txn.MSC3202DeviceLists)
	}
	if txn.DeviceOTKCount != nil {
		as.handleOTKCounts(ctx, txn.DeviceOTKCount)
	} else if txn.MSC3202DeviceOTKCount != nil {
		as.handleOTKCounts(ctx, txn.MSC3202DeviceOTKCount)
	}
	as.txnIDC.MarkProcessed(id)
	log.Debug().Msg("Finished dispatching events from transaction")
}

func (as *AppService) handleOTKCounts(ctx context.Context, otks OTKCountMap) {
	for userID, devices := range otks {
		for deviceID, otkCounts := range devices {
			otkCounts.UserID = userID
			otkCounts.DeviceID = deviceID
			select {
			case as.OTKCounts <- &otkCounts:
			default:
				zerolog.Ctx(ctx).Warn().
					Str("user_id", userID.String()).
					Msg("Dropped OTK count update for user because channel is full")
			}
		}
	}
}

func (as *AppService) handleDeviceLists(ctx context.Context, dl *mautrix.DeviceLists) {
	select {
	case as.DeviceLists <- dl:
	default:
		zerolog.Ctx(ctx).Warn().Msg("Dropped device list update because channel is full")
	}
}

func (as *AppService) handleEvents(ctx context.Context, evts []*event.Event, defaultTypeClass event.TypeClass) {
	log := zerolog.Ctx(ctx)
	for _, evt := range evts {
		evt.Mautrix.ReceivedAt = time.Now()
		if defaultTypeClass != event.UnknownEventType {
			if defaultTypeClass == event.EphemeralEventType {
				evt.Mautrix.EventSource = event.SourceEphemeral
			} else if defaultTypeClass == event.ToDeviceEventType {
				evt.Mautrix.EventSource = event.SourceToDevice
			}
			evt.Type.Class = defaultTypeClass
		} else if evt.StateKey != nil {
			evt.Mautrix.EventSource = event.SourceTimeline & event.SourceJoin
			evt.Type.Class = event.StateEventType
		} else {
			evt.Mautrix.EventSource = event.SourceTimeline
			evt.Type.Class = event.MessageEventType
		}
		err := evt.Content.ParseRaw(evt.Type)
		if errors.Is(err, event.ErrUnsupportedContentType) {
			log.Debug().Str("event_id", evt.ID.String()).Msg("Not parsing content of unsupported event")
		} else if err != nil {
			log.Warn().Err(err).
				Str("event_id", evt.ID.String()).
				Str("event_type", evt.Type.Type).
				Str("event_type_class", evt.Type.Class.Name()).
				Msg("Failed to parse content of event")
		}

		if evt.Type.IsState() {
			mautrix.UpdateStateStore(ctx, as.StateStore, evt)
		}
		var ch chan *event.Event
		if evt.Type.Class == event.ToDeviceEventType {
			ch = as.ToDeviceEvents
		} else {
			ch = as.Events
		}
		select {
		case ch <- evt:
		default:
			log.Warn().
				Str("event_id", evt.ID.String()).
				Str("event_type", evt.Type.Type).
				Str("event_type_class", evt.Type.Class.Name()).
				Msg("Event channel is full")
			ch <- evt
		}
	}
}

// GetRoom handles a /rooms GET call from the homeserver.
func (as *AppService) GetRoom(w http.ResponseWriter, r *http.Request) {
	if !as.CheckServerToken(w, r) {
		return
	}

	roomAlias := id.RoomAlias(r.PathValue("roomAlias"))
	ok := as.QueryHandler.QueryAlias(roomAlias)
	if ok {
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	} else {
		mautrix.MNotFound.WithMessage("Alias not found").Write(w)
	}
}

// GetUser handles a /users GET call from the homeserver.
func (as *AppService) GetUser(w http.ResponseWriter, r *http.Request) {
	if !as.CheckServerToken(w, r) {
		return
	}

	userID := id.UserID(r.PathValue("userID"))
	ok := as.QueryHandler.QueryUser(userID)
	if ok {
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	} else {
		mautrix.MNotFound.WithMessage("User not found").Write(w)
	}
}

func (as *AppService) PostPing(w http.ResponseWriter, r *http.Request) {
	if !as.CheckServerToken(w, r) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 || !json.Valid(body) {
		mautrix.MNotJSON.WithMessage("Invalid or missing request body").Write(w)
		return
	}

	var txn mautrix.ReqAppservicePing
	_ = json.Unmarshal(body, &txn)
	as.Log.Debug().Str("txn_id", txn.TxnID).Msg("Received ping from homeserver")

	exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
}

func (as *AppService) GetLive(w http.ResponseWriter, r *http.Request) {
	if as.Live {
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	} else {
		exhttp.WriteEmptyJSONResponse(w, http.StatusInternalServerError)
	}
}

func (as *AppService) GetReady(w http.ResponseWriter, r *http.Request) {
	if as.Ready {
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	} else {
		exhttp.WriteEmptyJSONResponse(w, http.StatusInternalServerError)
	}
}
