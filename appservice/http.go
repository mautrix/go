// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Start starts the HTTP server that listens for calls from the Matrix homeserver.
func (as *AppService) Start() {
	as.Router.HandleFunc("/transactions/{txnID}", as.PutTransaction).Methods(http.MethodPut)
	as.Router.HandleFunc("/rooms/{roomAlias}", as.GetRoom).Methods(http.MethodGet)
	as.Router.HandleFunc("/users/{userID}", as.GetUser).Methods(http.MethodGet)
	as.Router.HandleFunc("/_matrix/app/v1/transactions/{txnID}", as.PutTransaction).Methods(http.MethodPut)
	as.Router.HandleFunc("/_matrix/app/v1/rooms/{roomAlias}", as.GetRoom).Methods(http.MethodGet)
	as.Router.HandleFunc("/_matrix/app/v1/users/{userID}", as.GetUser).Methods(http.MethodGet)
	as.Router.HandleFunc("/_matrix/mau/live", as.GetLive).Methods(http.MethodGet)
	as.Router.HandleFunc("/_matrix/mau/ready", as.GetReady).Methods(http.MethodGet)

	var err error
	as.server = &http.Server{
		Addr:    as.Host.Address(),
		Handler: as.Router,
	}
	as.Log.Infoln("Listening on", as.Host.Address())
	if len(as.Host.TLSCert) == 0 || len(as.Host.TLSKey) == 0 {
		err = as.server.ListenAndServe()
	} else {
		err = as.server.ListenAndServeTLS(as.Host.TLSCert, as.Host.TLSKey)
	}
	if err != nil && err.Error() != "http: Server closed" {
		as.Log.Fatalln("Error while listening:", err)
	} else {
		as.Log.Debugln("Listener stopped.")
	}
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
	if len(authHeader) > 0 && strings.HasPrefix(authHeader, "Bearer ") {
		isValid = authHeader[len("Bearer "):] == as.Registration.ServerToken
	} else {
		queryToken := r.URL.Query().Get("access_token")
		if len(queryToken) > 0 {
			isValid = queryToken == as.Registration.ServerToken
		} else {
			Error{
				ErrorCode:  ErrUnknownToken,
				HTTPStatus: http.StatusForbidden,
				Message:    "Missing access token",
			}.Write(w)
			return
		}
	}
	if !isValid {
		Error{
			ErrorCode:  ErrUnknownToken,
			HTTPStatus: http.StatusForbidden,
			Message:    "Incorrect access token",
		}.Write(w)
	}
	return
}

// PutTransaction handles a /transactions PUT call from the homeserver.
func (as *AppService) PutTransaction(w http.ResponseWriter, r *http.Request) {
	if !as.CheckServerToken(w, r) {
		return
	}

	vars := mux.Vars(r)
	txnID := vars["txnID"]
	if len(txnID) == 0 {
		Error{
			ErrorCode:  ErrNoTransactionID,
			HTTPStatus: http.StatusBadRequest,
			Message:    "Missing transaction ID",
		}.Write(w)
		return
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		Error{
			ErrorCode:  ErrNotJSON,
			HTTPStatus: http.StatusBadRequest,
			Message:    "Missing request body",
		}.Write(w)
		return
	}
	if as.txnIDC.IsProcessed(txnID) {
		// Duplicate transaction ID: no-op
		WriteBlankOK(w)
		as.Log.Debugfln("Ignoring duplicate transaction %s", txnID)
		return
	}

	var txn Transaction
	err = json.Unmarshal(body, &txn)
	if err != nil {
		as.Log.Warnfln("Failed to parse JSON of transaction %s: %v", txnID, err)
		Error{
			ErrorCode:  ErrBadJSON,
			HTTPStatus: http.StatusBadRequest,
			Message:    "Failed to parse body JSON",
		}.Write(w)
	} else {
		as.handleTransaction(txnID, &txn)
		WriteBlankOK(w)
	}
}

func (as *AppService) handleTransaction(id string, txn *Transaction) {
	as.Log.Debugfln("Starting handling of transaction %s (%s)", id, txn.ContentString())
	if as.Registration.EphemeralEvents {
		if txn.EphemeralEvents != nil {
			as.handleEvents(txn.EphemeralEvents, event.EphemeralEventType)
		} else if txn.MSC2409EphemeralEvents != nil {
			as.handleEvents(txn.MSC2409EphemeralEvents, event.EphemeralEventType)
		}
		if txn.ToDeviceEvents != nil {
			as.handleEvents(txn.ToDeviceEvents, event.ToDeviceEventType)
		} else if txn.MSC2409ToDeviceEvents != nil {
			as.handleEvents(txn.MSC2409ToDeviceEvents, event.ToDeviceEventType)
		}
	}
	as.handleEvents(txn.Events, event.UnknownEventType)
	if txn.DeviceLists != nil {
		as.handleDeviceLists(txn.DeviceLists)
	} else if txn.MSC3202DeviceLists != nil {
		as.handleDeviceLists(txn.MSC3202DeviceLists)
	}
	if txn.DeviceOTKCount != nil {
		as.handleOTKCounts(txn.DeviceOTKCount)
	} else if txn.MSC3202DeviceOTKCount != nil {
		as.handleOTKCounts(txn.MSC3202DeviceOTKCount)
	}
	as.txnIDC.MarkProcessed(id)
}

func (as *AppService) handleOTKCounts(otks OTKCountMap) {
	for userID, devices := range otks {
		for deviceID, otkCounts := range devices {
			otkCounts.UserID = userID
			otkCounts.DeviceID = deviceID
			select {
			case as.OTKCounts <- &otkCounts:
			default:
				as.Log.Warnfln("Dropped OTK count update for %s because channel is full", userID)
			}
		}
	}
}

func (as *AppService) handleDeviceLists(dl *mautrix.DeviceLists) {
	select {
	case as.DeviceLists <- dl:
	default:
		as.Log.Warnln("Dropped device list update because channel is full")
	}
}

func (as *AppService) handleEvents(evts []*event.Event, defaultTypeClass event.TypeClass) {
	for _, evt := range evts {
		evt.Mautrix.ReceivedAt = time.Now()
		if defaultTypeClass != event.UnknownEventType {
			evt.Type.Class = defaultTypeClass
		} else if evt.StateKey != nil {
			evt.Type.Class = event.StateEventType
		} else {
			evt.Type.Class = event.MessageEventType
		}
		err := evt.Content.ParseRaw(evt.Type)
		if errors.Is(err, event.ErrUnsupportedContentType) {
			as.Log.Debugfln("Not parsing content of %s: %v", evt.ID, err)
		} else if err != nil {
			as.Log.Debugfln("Failed to parse content of %s (type %s): %v", evt.ID, evt.Type.Type, err)
		}

		if evt.Type.IsState() {
			// TODO remove this check after making sure the log doesn't happen
			historical, ok := evt.Content.Raw["org.matrix.msc2716.historical"].(bool)
			if ok && historical {
				as.Log.Warnfln("Received historical state event %s (%s/%s)", evt.ID, evt.Type.Type, evt.GetStateKey())
			} else {
				as.UpdateState(evt)
			}
		}
		if evt.Type.Class == event.ToDeviceEventType {
			as.ToDeviceEvents <- evt
		} else {
			as.Events <- evt
		}
	}
}

// GetRoom handles a /rooms GET call from the homeserver.
func (as *AppService) GetRoom(w http.ResponseWriter, r *http.Request) {
	if !as.CheckServerToken(w, r) {
		return
	}

	vars := mux.Vars(r)
	roomAlias := vars["roomAlias"]
	ok := as.QueryHandler.QueryAlias(roomAlias)
	if ok {
		WriteBlankOK(w)
	} else {
		Error{
			ErrorCode:  ErrUnknown,
			HTTPStatus: http.StatusNotFound,
		}.Write(w)
	}
}

// GetUser handles a /users GET call from the homeserver.
func (as *AppService) GetUser(w http.ResponseWriter, r *http.Request) {
	if !as.CheckServerToken(w, r) {
		return
	}

	vars := mux.Vars(r)
	userID := id.UserID(vars["userID"])
	ok := as.QueryHandler.QueryUser(userID)
	if ok {
		WriteBlankOK(w)
	} else {
		Error{
			ErrorCode:  ErrUnknown,
			HTTPStatus: http.StatusNotFound,
		}.Write(w)
	}
}

func (as *AppService) GetLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	if as.Live {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.Write([]byte("{}"))
}

func (as *AppService) GetReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	if as.Ready {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.Write([]byte("{}"))
}
