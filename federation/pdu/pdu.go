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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/tidwall/gjson"
	"go.mau.fi/util/jsonbytes"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/federation/signutil"
	"maunium.net/go/mautrix/id"
)

var ErrPDUIsNil = errors.New("PDU is nil")

type Hashes struct {
	SHA256 jsonbytes.UnpaddedBytes `json:"sha256"`

	Unknown jsontext.Value `json:",unknown"`
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

	Unknown jsontext.Value `json:",unknown"`

	// Deprecated legacy fields
	DeprecatedPrevState  any `json:"prev_state,omitzero"`
	DeprecatedOrigin     any `json:"origin,omitzero"`
	DeprecatedMembership any `json:"membership,omitzero"`
}

func (pdu *PDU) CalculateContentHash() ([32]byte, error) {
	if pdu == nil {
		return [32]byte{}, ErrPDUIsNil
	}
	pduClone := pdu.Clone()
	pduClone.Signatures = nil
	pduClone.Unsigned = nil
	pduClone.Hashes = nil
	rawJSON, err := marshalCanonical(pduClone)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to marshal PDU to calculate content hash: %w", err)
	}
	return sha256.Sum256(rawJSON), nil
}

func (pdu *PDU) FillContentHash() error {
	if pdu == nil {
		return ErrPDUIsNil
	} else if pdu.Hashes != nil {
		return nil
	} else if hash, err := pdu.CalculateContentHash(); err != nil {
		return err
	} else {
		pdu.Hashes = &Hashes{SHA256: hash[:]}
		return nil
	}
}

func (pdu *PDU) VerifyContentHash() bool {
	if pdu == nil || pdu.Hashes == nil {
		return false
	}
	calculatedHash, err := pdu.CalculateContentHash()
	if err != nil {
		return false
	}
	return hmac.Equal(calculatedHash[:], pdu.Hashes.SHA256)
}

func (pdu *PDU) Sign(roomVersion id.RoomVersion, serverName string, keyID id.KeyID, privateKey ed25519.PrivateKey) error {
	err := pdu.FillContentHash()
	if err != nil {
		return err
	}
	rawJSON, err := marshalCanonical(pdu.Clone().RedactForSignature(roomVersion))
	if err != nil {
		return fmt.Errorf("failed to marshal redacted PDU to sign: %w", err)
	}
	signature := ed25519.Sign(privateKey, rawJSON)
	if pdu.Signatures == nil {
		pdu.Signatures = make(map[string]map[id.KeyID]string)
	}
	if _, ok := pdu.Signatures[serverName]; !ok {
		pdu.Signatures[serverName] = make(map[id.KeyID]string)
	}
	pdu.Signatures[serverName][keyID] = base64.RawStdEncoding.EncodeToString(signature)
	return nil
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

func (pdu *PDU) VerifySignature(
	roomVersion id.RoomVersion,
	serverName string,
	getKey func(keyID id.KeyID, minValidUntil time.Time) (id.SigningKey, time.Time, error),
) error {
	rawJSON, err := marshalCanonical(pdu.Clone().RedactForSignature(roomVersion))
	if err != nil {
		return fmt.Errorf("failed to marshal redacted PDU to verify signature: %w", err)
	}
	verified := false
	for keyID, sig := range pdu.Signatures[serverName] {
		originServerTS := time.UnixMilli(pdu.OriginServerTS)
		key, validUntil, err := getKey(keyID, originServerTS)
		if err != nil {
			return fmt.Errorf("failed to get key %s for %s: %w", keyID, serverName, err)
		} else if key == "" {
			return fmt.Errorf("key %s not found for %s", keyID, serverName)
		} else if validUntil.Before(originServerTS) && roomVersion.EnforceSigningKeyValidity() {
			return fmt.Errorf("key %s for %s is only valid until %s, but event is from %s", keyID, serverName, validUntil, originServerTS)
		} else if err = signutil.VerifyJSONRaw(key, sig, rawJSON); err != nil {
			return fmt.Errorf("failed to verify signature from key %s: %w", keyID, err)
		} else {
			verified = true
		}
	}
	if !verified {
		return fmt.Errorf("no verifiable signatures found for server %s", serverName)
	}
	return nil
}

func (pdu *PDU) CalculateRoomID() (id.RoomID, error) {
	if pdu == nil {
		return "", ErrPDUIsNil
	} else if pdu.Type != "m.room.create" {
		return "", fmt.Errorf("room ID can only be calculated for m.room.create events")
	} else if roomVersion := id.RoomVersion(gjson.GetBytes(pdu.Content, "room_version").Str); !roomVersion.RoomIDIsCreateEventID() {
		return "", fmt.Errorf("room version %s does not use m.room.create event ID as room ID", roomVersion)
	} else if evtID, err := pdu.calculateEventID(roomVersion, '!'); err != nil {
		return "", fmt.Errorf("failed to calculate event ID: %w", err)
	} else {
		return id.RoomID(evtID), nil
	}
}

func (pdu *PDU) CalculateEventID(roomVersion id.RoomVersion) (id.EventID, error) {
	return pdu.calculateEventID(roomVersion, '$')
}

func (pdu *PDU) calculateEventID(roomVersion id.RoomVersion, prefix byte) (id.EventID, error) {
	if pdu == nil {
		return "", ErrPDUIsNil
	}
	if pdu.Hashes == nil || pdu.Hashes.SHA256 == nil {
		if err := pdu.FillContentHash(); err != nil {
			return "", err
		}
	}
	rawJSON, err := marshalCanonical(pdu.Clone().RedactForSignature(roomVersion))
	if err != nil {
		return "", fmt.Errorf("failed to marshal redacted PDU to calculate event ID: %w", err)
	}
	referenceHash := sha256.Sum256(rawJSON)
	eventID := make([]byte, 44)
	eventID[0] = prefix
	switch roomVersion.EventIDFormat() {
	case id.EventIDFormatCustom:
		return "", fmt.Errorf("*pdu.PDU can only be used for room v3+")
	case id.EventIDFormatBase64:
		base64.RawStdEncoding.Encode(eventID[1:], referenceHash[:])
	case id.EventIDFormatURLSafeBase64:
		base64.RawURLEncoding.Encode(eventID[1:], referenceHash[:])
	default:
		return "", fmt.Errorf("unknown event ID format %v", roomVersion.EventIDFormat())
	}
	return id.EventID(eventID), nil
}
