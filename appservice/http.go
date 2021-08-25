// Copyright (c) 2021 Tulir Asokan
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
	as.Router.HandleFunc("/health", as.GetHealth).Methods(http.MethodGet)

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
	if as.lastProcessedTransaction == txnID {
		// Duplicate transaction ID: no-op
		WriteBlankOK(w)
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
		as.handleTransaction(&txn)
		WriteBlankOK(w)
	}
	as.lastProcessedTransaction = txnID
}

func (as *AppService) handleTransaction(txn *Transaction) {
	if as.Registration.EphemeralEvents {
		if txn.EphemeralEvents != nil {
			as.handleEvents(txn.EphemeralEvents, event.EphemeralEventType)
		} else if txn.MSC2409EphemeralEvents != nil {
			as.handleEvents(txn.MSC2409EphemeralEvents, event.EphemeralEventType)
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
}

func (as *AppService) handleOTKCounts(otks map[id.UserID]mautrix.OTKCount) {
	for userID, otkCounts := range otks {
		otkCounts.UserID = userID
		select {
		case as.OTKCounts <- &otkCounts:
		default:
			as.Log.Warnfln("Dropped OTK count update for %s because channel is full", userID)
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
		if len(evt.ToUserID) > 0 {
			evt.Type.Class = event.ToDeviceEventType
		} else if defaultTypeClass != event.UnknownEventType {
			evt.Type.Class = defaultTypeClass
		} else if evt.StateKey != nil {
			evt.Type.Class = event.StateEventType
		} else {
			evt.Type.Class = event.MessageEventType
		}
		err := evt.Content.ParseRaw(evt.Type)
		if errors.Is(err, event.UnsupportedContentType) {
			as.Log.Debugfln("Not parsing content of %s: %v", evt.ID, err)
		} else if err != nil {
			as.Log.Debugfln("Failed to parse content of %s (type %s): %v", evt.ID, evt.Type.Type, err)
		}
		if evt.Type.IsState() {
			as.UpdateState(evt)
		}
		as.Events <- evt
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

// GetHealth responds with "OK".
func (as *AppService) GetHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
