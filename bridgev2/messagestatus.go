// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"errors"
	"fmt"

	"go.mau.fi/util/jsontime"

	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type MessageStatusEventInfo struct {
	RoomID        id.RoomID
	SourceEventID id.EventID
	NewEventID    id.EventID
	EventType     event.Type
	MessageType   event.MessageType
	Sender        id.UserID
	ThreadRoot    id.EventID
	StreamOrder   int64

	IsSourceEventDoublePuppeted bool
}

func StatusEventInfoFromEvent(evt *event.Event) *MessageStatusEventInfo {
	var threadRoot id.EventID
	if relatable, ok := evt.Content.Parsed.(event.Relatable); ok {
		threadRoot = relatable.OptionalGetRelatesTo().GetThreadParent()
	}

	_, isDoublePuppeted := evt.Content.Raw[appservice.DoublePuppetKey]

	return &MessageStatusEventInfo{
		RoomID:        evt.RoomID,
		SourceEventID: evt.ID,
		EventType:     evt.Type,
		MessageType:   evt.Content.AsMessage().MsgType,
		Sender:        evt.Sender,
		ThreadRoot:    threadRoot,

		IsSourceEventDoublePuppeted: isDoublePuppeted,
	}
}

// MessageStatus represents the status of a message. It also implements the error interface to allow network connectors
// to return errors which get translated into user-friendly error messages and/or status events.
type MessageStatus struct {
	Step     status.MessageCheckpointStep
	RetryNum int

	Status        event.MessageStatus
	ErrorReason   event.MessageStatusReason
	DeliveredTo   []id.UserID
	InternalError error  // Internal error to be tracked in message checkpoints
	Message       string // Human-readable message shown to users

	ErrorAsMessage bool
	IsCertain      bool
	SendNotice     bool
	DisableMSS     bool
}

func WrapErrorInStatus(err error) MessageStatus {
	var alreadyWrapped MessageStatus
	var ok bool
	if alreadyWrapped, ok = err.(MessageStatus); ok {
		return alreadyWrapped
	} else if errors.As(err, &alreadyWrapped) {
		alreadyWrapped.InternalError = err
		return alreadyWrapped
	}
	return MessageStatus{
		Status:        event.MessageStatusRetriable,
		ErrorReason:   event.MessageStatusGenericError,
		InternalError: err,
	}
}

func (ms MessageStatus) WithSendNotice(send bool) MessageStatus {
	ms.SendNotice = send
	return ms
}

func (ms MessageStatus) WithIsCertain(certain bool) MessageStatus {
	ms.IsCertain = certain
	return ms
}

func (ms MessageStatus) WithMessage(msg string) MessageStatus {
	ms.Message = msg
	ms.ErrorAsMessage = false
	return ms
}

func (ms MessageStatus) WithStep(step status.MessageCheckpointStep) MessageStatus {
	ms.Step = step
	return ms
}

func (ms MessageStatus) WithStatus(status event.MessageStatus) MessageStatus {
	ms.Status = status
	return ms
}

func (ms MessageStatus) WithErrorReason(reason event.MessageStatusReason) MessageStatus {
	ms.ErrorReason = reason
	return ms
}

func (ms MessageStatus) WithErrorAsMessage() MessageStatus {
	ms.ErrorAsMessage = true
	return ms
}

func (ms MessageStatus) Error() string {
	return ms.InternalError.Error()
}

func (ms MessageStatus) Unwrap() error {
	return ms.InternalError
}

func (ms *MessageStatus) checkpointStatus() status.MessageCheckpointStatus {
	switch ms.Status {
	case event.MessageStatusSuccess:
		if len(ms.DeliveredTo) > 0 {
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

func (ms *MessageStatus) ToCheckpoint(evt *MessageStatusEventInfo) *status.MessageCheckpoint {
	step := status.MsgStepRemote
	if ms.Step != "" {
		step = ms.Step
	}
	checkpoint := &status.MessageCheckpoint{
		RoomID:      evt.RoomID,
		EventID:     evt.SourceEventID,
		Step:        step,
		Timestamp:   jsontime.UnixMilliNow(),
		Status:      ms.checkpointStatus(),
		RetryNum:    ms.RetryNum,
		ReportedBy:  status.MsgReportedByBridge,
		EventType:   evt.EventType,
		MessageType: evt.MessageType,
	}
	if ms.InternalError != nil {
		checkpoint.Info = ms.InternalError.Error()
	} else if ms.Message != "" {
		checkpoint.Info = ms.Message
	}
	return checkpoint
}

func (ms *MessageStatus) ToMSSEvent(evt *MessageStatusEventInfo) *event.BeeperMessageStatusEventContent {
	content := &event.BeeperMessageStatusEventContent{
		RelatesTo: event.RelatesTo{
			Type:    event.RelReference,
			EventID: evt.SourceEventID,
		},
		Status:  ms.Status,
		Reason:  ms.ErrorReason,
		Message: ms.Message,
	}
	if ms.InternalError != nil {
		content.InternalError = ms.InternalError.Error()
		if ms.ErrorAsMessage {
			content.Message = content.InternalError
		}
	}
	if ms.DeliveredTo != nil {
		content.DeliveredToUsers = &ms.DeliveredTo
	}
	return content
}

func (ms *MessageStatus) ToNoticeEvent(evt *MessageStatusEventInfo) *event.MessageEventContent {
	certainty := "may not have been"
	if ms.IsCertain {
		certainty = "was not"
	}
	evtType := "message"
	switch evt.EventType {
	case event.EventReaction:
		evtType = "reaction"
	case event.EventRedaction:
		evtType = "redaction"
	}
	msg := ms.Message
	if ms.ErrorAsMessage || msg == "" {
		msg = ms.InternalError.Error()
	}
	messagePrefix := fmt.Sprintf("Your %s %s bridged", evtType, certainty)
	if ms.Step == status.MsgStepCommand {
		messagePrefix = "Handling your command panicked"
	}
	content := &event.MessageEventContent{
		MsgType:   event.MsgNotice,
		Body:      fmt.Sprintf("\u26a0\ufe0f %s: %s", messagePrefix, msg),
		RelatesTo: &event.RelatesTo{},
		Mentions:  &event.Mentions{},
	}
	if evt.ThreadRoot != "" {
		content.RelatesTo.SetThread(evt.ThreadRoot, evt.SourceEventID)
	} else {
		content.RelatesTo.SetReplyTo(evt.SourceEventID)
	}
	if evt.Sender != "" {
		content.Mentions.UserIDs = []id.UserID{evt.Sender}
	}
	return content
}
