// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/json"

	"maunium.net/go/mautrix/id"
)

// TypingEventContent represents the content of a m.typing ephemeral event.
// https://spec.matrix.org/v1.2/client-server-api/#mtyping
type TypingEventContent struct {
	UserIDs []id.UserID `json:"user_ids"`
}

// ReceiptEventContent represents the content of a m.receipt ephemeral event.
// https://spec.matrix.org/v1.2/client-server-api/#mreceipt
type ReceiptEventContent map[id.EventID]Receipts

func (rec ReceiptEventContent) Set(evtID id.EventID, receiptType ReceiptType, userID id.UserID, receipt ReadReceipt) {
	rec.GetOrCreate(evtID).GetOrCreate(receiptType).Set(userID, receipt)
}

func (rec ReceiptEventContent) GetOrCreate(evt id.EventID) Receipts {
	receipts, ok := rec[evt]
	if !ok {
		receipts = make(Receipts)
		rec[evt] = receipts
	}
	return receipts
}

type ReceiptType string

const (
	ReceiptTypeRead        ReceiptType = "m.read"
	ReceiptTypeReadPrivate ReceiptType = "m.read.private"
)

type Receipts map[ReceiptType]UserReceipts

func (rps Receipts) GetOrCreate(receiptType ReceiptType) UserReceipts {
	read, ok := rps[receiptType]
	if !ok {
		read = make(UserReceipts)
		rps[receiptType] = read
	}
	return read
}

type UserReceipts map[id.UserID]ReadReceipt

func (ur UserReceipts) Set(userID id.UserID, receipt ReadReceipt) {
	ur[userID] = receipt
}

type ReadReceipt struct {
	Timestamp int64 `json:"ts"`

	// Extra contains any unknown fields in the read receipt event.
	// Most servers don't allow clients to set them, so this will be empty in most cases.
	Extra map[string]interface{} `json:"-"`
}

func (rr *ReadReceipt) UnmarshalJSON(data []byte) error {
	// Hacky compatibility hack against crappy clients that send double-encoded read receipts.
	// TODO is this actually needed? clients can't currently set custom content in receipts 🤔
	if data[0] == '"' && data[len(data)-1] == '"' {
		var strData string
		err := json.Unmarshal(data, &strData)
		if err != nil {
			return err
		}
		data = []byte(strData)
	}

	var parsed map[string]interface{}
	err := json.Unmarshal(data, &parsed)
	if err != nil {
		return err
	}
	ts, _ := parsed["ts"].(float64)
	delete(parsed, "ts")
	*rr = ReadReceipt{
		Timestamp: int64(ts),
		Extra:     parsed,
	}
	return nil
}

type Presence string

const (
	PresenceOnline      Presence = "online"
	PresenceOffline     Presence = "offline"
	PresenceUnavailable Presence = "unavailable"
)

// PresenceEventContent represents the content of a m.presence ephemeral event.
// https://spec.matrix.org/v1.2/client-server-api/#mpresence
type PresenceEventContent struct {
	Presence        Presence            `json:"presence"`
	Displayname     string              `json:"displayname,omitempty"`
	AvatarURL       id.ContentURIString `json:"avatar_url,omitempty"`
	LastActiveAgo   int64               `json:"last_active_ago,omitempty"`
	CurrentlyActive bool                `json:"currently_active,omitempty"`
	StatusMessage   string              `json:"status_msg,omitempty"`
}
