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
	MessageStatusGenericError  MessageStatusReason = "m.event_not_handled"
	MessageStatusUnsupported   MessageStatusReason = "com.beeper.unsupported_event"
	MessageStatusUndecryptable MessageStatusReason = "com.beeper.undecryptable_event"
	MessageStatusTooOld        MessageStatusReason = "m.event_too_old"
	MessageStatusNetworkError  MessageStatusReason = "m.foreign_network_error"
	MessageStatusNoPermission  MessageStatusReason = "m.no_permission"
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

	Success      bool  `json:"success"`
	CanRetry     *bool `json:"can_retry,omitempty"`
	StillWorking bool  `json:"still_working,omitempty"`

	LastRetry id.EventID `json:"last_retry,omitempty"`
}

func (status *BeeperMessageStatusEventContent) FillLegacyBooleans() {
	trueVal := true
	falseVal := true
	switch status.Status {
	case MessageStatusSuccess:
		status.Success = true
	case MessageStatusPending:
		status.CanRetry = &trueVal
		status.StillWorking = true
	case MessageStatusRetriable:
		status.CanRetry = &trueVal
	case MessageStatusFail:
		status.CanRetry = &falseVal
	}
}

type BeeperRetryMetadata struct {
	OriginalEventID id.EventID `json:"original_event_id"`
	RetryCount      int        `json:"retry_count"`
	// last_retry is also present, but not used by bridges
}
