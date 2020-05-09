// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Listen starts the HTTP server that listens for calls from the Matrix homeserver.
func (as *AppService) Start() {
	as.Router.HandleFunc("/transactions/{txnID}", as.PutTransaction).Methods(http.MethodPut)
	as.Router.HandleFunc("/rooms/{roomAlias}", as.GetRoom).Methods(http.MethodGet)
	as.Router.HandleFunc("/users/{userID}", as.GetUser).Methods(http.MethodGet)
	as.Router.HandleFunc("/_matrix/app/v1/transactions/{txnID}", as.PutTransaction).Methods(http.MethodPut)
	as.Router.HandleFunc("/_matrix/app/v1/rooms/{roomAlias}", as.GetRoom).Methods(http.MethodGet)
	as.Router.HandleFunc("/_matrix/app/v1/users/{userID}", as.GetUser).Methods(http.MethodGet)

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

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	_ = as.server.Shutdown(ctx)
	as.server = nil
}

// CheckServerToken checks if the given request originated from the Matrix homeserver.
func (as *AppService) CheckServerToken(w http.ResponseWriter, r *http.Request) bool {
	query := r.URL.Query()
	val, ok := query["access_token"]
	if !ok {
		Error{
			ErrorCode:  ErrForbidden,
			HTTPStatus: http.StatusForbidden,
			Message:    "Bad token supplied.",
		}.Write(w)
		return false
	}
	for _, str := range val {
		return str == as.Registration.ServerToken
	}
	return false
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
			Message:    "Missing transaction ID.",
		}.Write(w)
		return
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		Error{
			ErrorCode:  ErrNoBody,
			HTTPStatus: http.StatusBadRequest,
			Message:    "Missing request body.",
		}.Write(w)
		return
	}
	if as.lastProcessedTransaction == txnID {
		// Duplicate transaction ID: no-op
		WriteBlankOK(w)
		return
	}

	eventList := EventList{}
	err = json.Unmarshal(body, &eventList)
	if err != nil {
		as.Log.Warnfln("Failed to parse JSON of transaction %s: %v", txnID, err)
		Error{
			ErrorCode:  ErrInvalidJSON,
			HTTPStatus: http.StatusBadRequest,
			Message:    "Failed to parse body JSON.",
		}.Write(w)
	} else {
		for _, evt := range eventList.Events {
			if evt.StateKey != nil {
				evt.Type.Class = event.StateEventType
			} else {
				evt.Type.Class = event.MessageEventType
			}
			err := evt.Content.ParseRaw(evt.Type)
			if err != nil {
				as.Log.Debugfln("Failed to parse content of %s: %v", evt.ID, err)
			}
			as.UpdateState(evt)
			as.Events <- evt
		}
		WriteBlankOK(w)
	}
	as.lastProcessedTransaction = txnID
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
