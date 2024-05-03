// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type MessageStatus struct {
	RoomID      id.RoomID
	EventID     id.EventID
	Status      event.MessageStatus
	ErrorReason event.MessageStatusReason
	DeliveredTo []id.UserID
	Error       error  // Internal error to be tracked in message checkpoints
	Message     string // Human-readable message shown to users
}

func (ms *MessageStatus) CheckpointStatus() status.MessageCheckpointStatus {
	switch ms.Status {
	case event.MessageStatusSuccess:
		if ms.DeliveredTo != nil {
			return status.MsgStatusDelivered
		}
		return status.MsgStatusSuccess
	case event.MessageStatusPending:
		return status.MsgStatusWillRetry
	case event.MessageStatusRetriable, event.MessageStatusFail:
		switch ms.ErrorReason {
		case event.MessageStatusTooOld:
			return status.MsgStatusTimeout
		case event.MessageStatusUnsupported:
			return status.MsgStatusUnsupported
		default:
			return status.MsgStatusPermFailure
		}
	default:
		return "UNKNOWN"
	}
}

func (ms *MessageStatus) ToCheckpoint() *status.MessageCheckpoint {
	checkpoint := &status.MessageCheckpoint{
		RoomID:     ms.RoomID,
		EventID:    ms.EventID,
		Step:       status.MsgStepRemote,
		Status:     ms.CheckpointStatus(),
		ReportedBy: status.MsgReportedByBridge,
	}
	if ms.Error != nil {
		checkpoint.Info = ms.Error.Error()
	} else if ms.Message != "" {
		checkpoint.Info = ms.Message
	}
	return checkpoint
}

func (ms *MessageStatus) ToEvent() *event.BeeperMessageStatusEventContent {
	content := &event.BeeperMessageStatusEventContent{
		RelatesTo: event.RelatesTo{
			Type:    event.RelAnnotation,
			EventID: ms.EventID,
		},
		Status:  ms.Status,
		Reason:  ms.ErrorReason,
		Message: ms.Message,
	}
	if ms.Error != nil {
		content.InternalError = ms.Error.Error()
	}
	if ms.DeliveredTo != nil {
		content.DeliveredToUsers = &ms.DeliveredTo
	}
	return content
}

func (ms *MessageStatus) ErrorAsMessage() *MessageStatus {
	ms.Message = ms.Error.Error()
	return ms
}
