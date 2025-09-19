// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/tidwall/gjson"

	"maunium.net/go/mautrix/id"
)

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

func (pdu *PDU) GetRoomID() (id.RoomID, error) {
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

var UseInternalMetaForGetEventID = false

func (pdu *PDU) GetEventID(roomVersion id.RoomVersion) (id.EventID, error) {
	if UseInternalMetaForGetEventID && pdu.InternalMeta.EventID != "" {
		return pdu.InternalMeta.EventID, nil
	}
	return pdu.calculateEventID(roomVersion, '$')
}

func (pdu *PDU) GetReferenceHash(roomVersion id.RoomVersion) ([32]byte, error) {
	if pdu == nil {
		return [32]byte{}, ErrPDUIsNil
	}
	if pdu.Hashes == nil || pdu.Hashes.SHA256 == nil {
		if err := pdu.FillContentHash(); err != nil {
			return [32]byte{}, err
		}
	}
	rawJSON, err := marshalCanonical(pdu.Clone().RedactForSignature(roomVersion))
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to marshal redacted PDU to calculate event ID: %w", err)
	}
	return sha256.Sum256(rawJSON), nil
}

func (pdu *PDU) calculateEventID(roomVersion id.RoomVersion, prefix byte) (id.EventID, error) {
	referenceHash, err := pdu.GetReferenceHash(roomVersion)
	if err != nil {
		return "", err
	}
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
