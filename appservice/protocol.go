// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"encoding/json"
	"net/http"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Transaction contains a list of events.
type Transaction struct {
	Events          []*event.Event                 `json:"events"`
	EphemeralEvents []*event.Event                 `json:"ephemeral,omitempty"`
	DeviceLists     *mautrix.DeviceLists           `json:"device_lists,omitempty"`
	DeviceOTKCount  map[id.UserID]mautrix.OTKCount `json:"device_one_time_keys_count,omitempty"`

	MSC2409EphemeralEvents []*event.Event                 `json:"de.sorunome.msc2409.ephemeral,omitempty"`
	MSC3202DeviceLists     *mautrix.DeviceLists           `json:"org.matrix.msc3202.device_lists,omitempty"`
	MSC3202DeviceOTKCount  map[id.UserID]mautrix.OTKCount `json:"org.matrix.msc3202.device_one_time_keys_count,omitempty"`
}

// EventListener is a function that receives events.
type EventListener func(evt *event.Event)

// WriteBlankOK writes a blank OK message as a reply to a HTTP request.
func WriteBlankOK(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

// Respond responds to a HTTP request with a JSON object.
func Respond(w http.ResponseWriter, data interface{}) error {
	w.Header().Add("Content-Type", "application/json")
	dataStr, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = w.Write(dataStr)
	return err
}

// Error represents a Matrix protocol error.
type Error struct {
	HTTPStatus int       `json:"-"`
	ErrorCode  ErrorCode `json:"errcode"`
	Message    string    `json:"error"`
}

func (err Error) Write(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus)
	_ = Respond(w, &err)
}

// ErrorCode is the machine-readable code in an Error.
type ErrorCode string

// Native ErrorCodes
const (
	ErrUnknownToken ErrorCode = "M_UNKNOWN_TOKEN"
	ErrBadJSON      ErrorCode = "M_BAD_JSON"
	ErrNotJSON      ErrorCode = "M_NOT_JSON"
	ErrUnknown      ErrorCode = "M_UNKNOWN"
)

// Custom ErrorCodes
const (
	ErrNoTransactionID ErrorCode = "NET.MAUNIUM.NO_TRANSACTION_ID"
)
