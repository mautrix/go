// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"go.mau.fi/util/jsonbytes"
	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// GetKeyFunc is a callback for retrieving the key corresponding to a given key ID when verifying the signature of a PDU.
//
// The input time is the timestamp of the event. The function should attempt to fetch a key that is
// valid at or after this time, but if that is not possible, the latest available key should be
// returned without an error. The verify function will do its own validity checking based on the
// returned valid until timestamp.
type GetKeyFunc = func(serverName string, keyID id.KeyID, minValidUntil time.Time) (key id.SigningKey, validUntil time.Time, err error)

type AnyPDU interface {
	GetRoomID() (id.RoomID, error)
	GetEventID(roomVersion id.RoomVersion) (id.EventID, error)
	GetReferenceHash(roomVersion id.RoomVersion) ([32]byte, error)
	CalculateContentHash() ([32]byte, error)
	FillContentHash() error
	VerifyContentHash() bool
	Sign(roomVersion id.RoomVersion, serverName string, keyID id.KeyID, privateKey ed25519.PrivateKey) error
	VerifySignature(roomVersion id.RoomVersion, serverName string, getKey GetKeyFunc) error
	ToClientEvent(roomVersion id.RoomVersion) (*event.Event, error)
	AuthEventSelection(roomVersion id.RoomVersion) (keys AuthEventSelection)
}

var (
	_ AnyPDU = (*PDU)(nil)
	_ AnyPDU = (*RoomV1PDU)(nil)
)

type InternalMeta struct {
	EventID  id.EventID     `json:"event_id,omitempty"`
	Rejected bool           `json:"rejected,omitempty"`
	Extra    map[string]any `json:",unknown"`
}

type PDU struct {
	AuthEvents     []id.EventID                   `json:"auth_events"`
	Content        jsontext.Value                 `json:"content"`
	Depth          int64                          `json:"depth"`
	Hashes         *Hashes                        `json:"hashes,omitzero"`
	OriginServerTS int64                          `json:"origin_server_ts"`
	PrevEvents     []id.EventID                   `json:"prev_events"`
	Redacts        *id.EventID                    `json:"redacts,omitzero"`
	RoomID         id.RoomID                      `json:"room_id,omitzero"` // not present for room v12+ create events
	Sender         id.UserID                      `json:"sender"`
	Signatures     map[string]map[id.KeyID]string `json:"signatures,omitzero"`
	StateKey       *string                        `json:"state_key,omitzero"`
	Type           string                         `json:"type"`
	Unsigned       jsontext.Value                 `json:"unsigned,omitzero"`
	InternalMeta   InternalMeta                   `json:"-"`

	Unknown jsontext.Value `json:",unknown"`

	// Deprecated legacy fields
	DeprecatedPrevState  jsontext.Value `json:"prev_state,omitzero"`
	DeprecatedOrigin     jsontext.Value `json:"origin,omitzero"`
	DeprecatedMembership jsontext.Value `json:"membership,omitzero"`
}

var ErrPDUIsNil = errors.New("PDU is nil")

type Hashes struct {
	SHA256 jsonbytes.UnpaddedBytes `json:"sha256"`

	Unknown jsontext.Value `json:",unknown"`
}

func (pdu *PDU) ToClientEvent(roomVersion id.RoomVersion) (*event.Event, error) {
	if pdu.Type == "m.room.create" && roomVersion == "" {
		roomVersion = id.RoomVersion(gjson.GetBytes(pdu.Content, "room_version").Str)
	}
	evtType := event.Type{Type: pdu.Type, Class: event.MessageEventType}
	if pdu.StateKey != nil {
		evtType.Class = event.StateEventType
	}
	eventID, err := pdu.GetEventID(roomVersion)
	if err != nil {
		return nil, err
	}
	roomID := pdu.RoomID
	if pdu.Type == "m.room.create" && roomVersion.RoomIDIsCreateEventID() {
		roomID = id.RoomID(strings.Replace(string(eventID), "$", "!", 1))
	}
	evt := &event.Event{
		StateKey:  pdu.StateKey,
		Sender:    pdu.Sender,
		Type:      evtType,
		Timestamp: pdu.OriginServerTS,
		ID:        eventID,
		RoomID:    roomID,
		Redacts:   ptr.Val(pdu.Redacts),
	}
	err = json.Unmarshal(pdu.Content, &evt.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal content: %w", err)
	}
	return evt, nil
}

func marshalCanonical(data any) (jsontext.Value, error) {
	marshaledBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	marshaled := jsontext.Value(marshaledBytes)
	err = marshaled.Canonicalize()
	if err != nil {
		return nil, err
	}
	check := canonicaljson.CanonicalJSONAssumeValid(marshaled)
	if !bytes.Equal(marshaled, check) {
		fmt.Println(string(marshaled))
		fmt.Println(string(check))
		return nil, fmt.Errorf("canonical JSON mismatch for %s", string(marshaled))
	}
	return marshaled, nil
}
