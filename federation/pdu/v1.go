// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/tidwall/gjson"
	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation/signutil"
	"maunium.net/go/mautrix/id"
)

type V1EventReference struct {
	ID     id.EventID
	Hashes Hashes
}

var (
	_ json.UnmarshalerFrom = (*V1EventReference)(nil)
	_ json.MarshalerTo     = (*V1EventReference)(nil)
)

func (er *V1EventReference) MarshalJSONTo(enc *jsontext.Encoder) error {
	return json.MarshalEncode(enc, []any{er.ID, er.Hashes})
}

func (er *V1EventReference) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var ref V1EventReference
	var data []jsontext.Value
	if err := json.UnmarshalDecode(dec, &data); err != nil {
		return err
	} else if len(data) != 2 {
		return fmt.Errorf("V1EventReference.UnmarshalJSONFrom: expected array with 2 elements, got %d", len(data))
	} else if err = json.Unmarshal(data[0], &ref.ID); err != nil {
		return fmt.Errorf("V1EventReference.UnmarshalJSONFrom: failed to unmarshal event ID: %w", err)
	} else if err = json.Unmarshal(data[1], &ref.Hashes); err != nil {
		return fmt.Errorf("V1EventReference.UnmarshalJSONFrom: failed to unmarshal hashes: %w", err)
	}
	*er = ref
	return nil
}

type RoomV1PDU struct {
	AuthEvents     []V1EventReference             `json:"auth_events"`
	Content        jsontext.Value                 `json:"content"`
	Depth          int64                          `json:"depth"`
	EventID        id.EventID                     `json:"event_id"`
	Hashes         *Hashes                        `json:"hashes,omitzero"`
	OriginServerTS int64                          `json:"origin_server_ts"`
	PrevEvents     []V1EventReference             `json:"prev_events"`
	Redacts        *id.EventID                    `json:"redacts,omitzero"`
	RoomID         id.RoomID                      `json:"room_id"`
	Sender         id.UserID                      `json:"sender"`
	Signatures     map[string]map[id.KeyID]string `json:"signatures,omitzero"`
	StateKey       *string                        `json:"state_key,omitzero"`
	Type           string                         `json:"type"`
	Unsigned       jsontext.Value                 `json:"unsigned,omitzero"`

	Unknown jsontext.Value `json:",unknown"`

	// Deprecated legacy fields
	DeprecatedPrevState  jsontext.Value `json:"prev_state,omitzero"`
	DeprecatedOrigin     jsontext.Value `json:"origin,omitzero"`
	DeprecatedMembership jsontext.Value `json:"membership,omitzero"`
}

func (pdu *RoomV1PDU) GetRoomID() (id.RoomID, error) {
	return pdu.RoomID, nil
}

func (pdu *RoomV1PDU) GetEventID(roomVersion id.RoomVersion) (id.EventID, error) {
	if !pdu.SupportsRoomVersion(roomVersion) {
		return "", fmt.Errorf("RoomV1PDU.GetEventID: unsupported room version %s", roomVersion)
	}
	return pdu.EventID, nil
}

func (pdu *RoomV1PDU) RedactForSignature(roomVersion id.RoomVersion) *RoomV1PDU {
	pdu.Signatures = nil
	return pdu.Redact(roomVersion)
}

func (pdu *RoomV1PDU) Redact(roomVersion id.RoomVersion) *RoomV1PDU {
	pdu.Unknown = nil
	pdu.Unsigned = nil
	if pdu.Type != "m.room.redaction" {
		pdu.Redacts = nil
	}
	pdu.Content = RedactContent(pdu.Type, pdu.Content, roomVersion)
	return pdu
}

func (pdu *RoomV1PDU) GetReferenceHash(roomVersion id.RoomVersion) ([32]byte, error) {
	if !pdu.SupportsRoomVersion(roomVersion) {
		return [32]byte{}, fmt.Errorf("RoomV1PDU.GetReferenceHash: unsupported room version %s", roomVersion)
	}
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

func (pdu *RoomV1PDU) CalculateContentHash() ([32]byte, error) {
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

func (pdu *RoomV1PDU) FillContentHash() error {
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

func (pdu *RoomV1PDU) VerifyContentHash() bool {
	if pdu == nil || pdu.Hashes == nil {
		return false
	}
	calculatedHash, err := pdu.CalculateContentHash()
	if err != nil {
		return false
	}
	return hmac.Equal(calculatedHash[:], pdu.Hashes.SHA256)
}

func (pdu *RoomV1PDU) Clone() *RoomV1PDU {
	return ptr.Clone(pdu)
}

func (pdu *RoomV1PDU) Sign(roomVersion id.RoomVersion, serverName string, keyID id.KeyID, privateKey ed25519.PrivateKey) error {
	if !pdu.SupportsRoomVersion(roomVersion) {
		return fmt.Errorf("RoomV1PDU.Sign: unsupported room version %s", roomVersion)
	}
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

func (pdu *RoomV1PDU) VerifySignature(roomVersion id.RoomVersion, serverName string, getKey GetKeyFunc) error {
	if !pdu.SupportsRoomVersion(roomVersion) {
		return fmt.Errorf("RoomV1PDU.VerifySignature: unsupported room version %s", roomVersion)
	}
	rawJSON, err := marshalCanonical(pdu.Clone().RedactForSignature(roomVersion))
	if err != nil {
		return fmt.Errorf("failed to marshal redacted PDU to verify signature: %w", err)
	}
	verified := false
	for keyID, sig := range pdu.Signatures[serverName] {
		originServerTS := time.UnixMilli(pdu.OriginServerTS)
		key, _, err := getKey(serverName, keyID, originServerTS)
		if err != nil {
			return fmt.Errorf("failed to get key %s for %s: %w", keyID, serverName, err)
		} else if key == "" {
			return fmt.Errorf("key %s not found for %s", keyID, serverName)
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

func (pdu *RoomV1PDU) SupportsRoomVersion(roomVersion id.RoomVersion) bool {
	switch roomVersion {
	case id.RoomV0, id.RoomV1, id.RoomV2:
		return true
	default:
		return false
	}
}

func (pdu *RoomV1PDU) ToClientEvent(roomVersion id.RoomVersion) (*event.Event, error) {
	if !pdu.SupportsRoomVersion(roomVersion) {
		return nil, fmt.Errorf("RoomV1PDU.ToClientEvent: unsupported room version %s", roomVersion)
	}
	evtType := event.Type{Type: pdu.Type, Class: event.MessageEventType}
	if pdu.StateKey != nil {
		evtType.Class = event.StateEventType
	}
	evt := &event.Event{
		StateKey:  pdu.StateKey,
		Sender:    pdu.Sender,
		Type:      evtType,
		Timestamp: pdu.OriginServerTS,
		ID:        pdu.EventID,
		RoomID:    pdu.RoomID,
		Redacts:   ptr.Val(pdu.Redacts),
	}
	err := json.Unmarshal(pdu.Content, &evt.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal content: %w", err)
	}
	return evt, nil
}

func (pdu *RoomV1PDU) AuthEventSelection(_ id.RoomVersion) (keys AuthEventSelection) {
	if pdu.Type == event.StateCreate.Type && pdu.StateKey != nil {
		return AuthEventSelection{}
	}
	keys = make(AuthEventSelection, 0, 3)
	keys.Add(event.StateCreate.Type, "")
	keys.Add(event.StatePowerLevels.Type, "")
	keys.Add(event.StateMember.Type, pdu.Sender.String())
	if pdu.Type == event.StateMember.Type && pdu.StateKey != nil {
		keys.Add(event.StateMember.Type, *pdu.StateKey)
		membership := event.Membership(gjson.GetBytes(pdu.Content, "membership").Str)
		if membership == event.MembershipJoin || membership == event.MembershipInvite || membership == event.MembershipKnock {
			keys.Add(event.StateJoinRules.Type, "")
		}
		if membership == event.MembershipInvite {
			thirdPartyInviteToken := gjson.GetBytes(pdu.Content, thirdPartyInviteTokenPath).Str
			if thirdPartyInviteToken != "" {
				keys.Add(event.StateThirdPartyInvite.Type, thirdPartyInviteToken)
			}
		}
	}
	return
}
