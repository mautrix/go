// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"maunium.net/go/mautrix/id"
)

type MessageStatusReason string

const (
	MessageStatusGenericError      MessageStatusReason = "m.event_not_handled"
	MessageStatusUnsupported       MessageStatusReason = "com.beeper.unsupported_event"
	MessageStatusUndecryptable     MessageStatusReason = "com.beeper.undecryptable_event"
	MessageStatusTooOld            MessageStatusReason = "m.event_too_old"
	MessageStatusNetworkError      MessageStatusReason = "m.foreign_network_error"
	MessageStatusNoPermission      MessageStatusReason = "m.no_permission"
	MessageStatusBridgeUnavailable MessageStatusReason = "m.bridge_unavailable"
)

type MessageStatus string

const (
	MessageStatusSuccess   MessageStatus = "SUCCESS"
	MessageStatusPending   MessageStatus = "PENDING"
	MessageStatusRetriable MessageStatus = "FAIL_RETRIABLE"
	MessageStatusFail      MessageStatus = "FAIL_PERMANENT"
)

type BeeperMessageStatusEventContent struct {
	Network   string              `json:"network"`
	RelatesTo RelatesTo           `json:"m.relates_to"`
	Status    MessageStatus       `json:"status"`
	Reason    MessageStatusReason `json:"reason,omitempty"`
	Error     string              `json:"error,omitempty"`
	Message   string              `json:"message,omitempty"`

	LastRetry id.EventID `json:"last_retry,omitempty"`

	MutateEventKey string `json:"mutate_event_key,omitempty"`

	// Indicates the set of users to whom the event was delivered. If nil, then
	// the client should not expect delivered status at any later point. If not
	// nil (even if empty), this field indicates which users the event was
	// delivered to.
	DeliveredToUsers *[]id.UserID `json:"delivered_to_users,omitempty"`
}

type BeeperRetryMetadata struct {
	OriginalEventID id.EventID `json:"original_event_id"`
	RetryCount      int        `json:"retry_count"`
	// last_retry is also present, but not used by bridges
}

type BeeperRoomKeyAckEventContent struct {
	RoomID            id.RoomID    `json:"room_id"`
	SessionID         id.SessionID `json:"session_id"`
	FirstMessageIndex int          `json:"first_message_index"`
}
