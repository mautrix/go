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

	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	ErrIgnoringRemoteEvent = errors.New("ignoring remote event")
	ErrNoStatus            = errors.New("omit message status")

	ErrPanicInEventHandler             error = WrapErrorInStatus(errors.New("panic in event handler")).WithSendNotice(true).WithErrorAsMessage()
	ErrNoPortal                        error = WrapErrorInStatus(errors.New("room is not a portal")).WithIsCertain(true).WithSendNotice(false)
	ErrIgnoringReactionFromRelayedUser error = WrapErrorInStatus(errors.New("ignoring reaction event from relayed user")).WithIsCertain(true).WithSendNotice(false)
	ErrEditsNotSupported               error = WrapErrorInStatus(errors.New("this bridge does not support edits")).WithIsCertain(true).WithErrorAsMessage()
	ErrEditsNotSupportedInPortal       error = WrapErrorInStatus(errors.New("edits are not allowed in this chat")).WithIsCertain(true).WithErrorAsMessage()
	ErrCaptionsNotAllowed              error = WrapErrorInStatus(errors.New("captions are not supported here")).WithIsCertain(true).WithErrorAsMessage()
	ErrLocationMessagesNotAllowed      error = WrapErrorInStatus(errors.New("location messages are not supported here")).WithIsCertain(true).WithErrorAsMessage()
	ErrEditTargetTooOld                error = WrapErrorInStatus(errors.New("the message is too old to be edited")).WithIsCertain(true).WithErrorAsMessage()
	ErrEditTargetTooManyEdits          error = WrapErrorInStatus(errors.New("the message has been edited too many times")).WithIsCertain(true).WithErrorAsMessage()
	ErrReactionsNotSupported           error = WrapErrorInStatus(errors.New("this bridge does not support reactions")).WithIsCertain(true).WithErrorAsMessage()
	ErrRoomMetadataNotSupported        error = WrapErrorInStatus(errors.New("this bridge does not support changing room metadata")).WithIsCertain(true).WithErrorAsMessage().WithSendNotice(false)
	ErrRedactionsNotSupported          error = WrapErrorInStatus(errors.New("this bridge does not support deleting messages")).WithIsCertain(true).WithErrorAsMessage()
	ErrUnexpectedParsedContentType     error = WrapErrorInStatus(errors.New("unexpected parsed content type")).WithErrorAsMessage().WithIsCertain(true).WithSendNotice(true)
	ErrDatabaseError                   error = WrapErrorInStatus(errors.New("database error")).WithMessage("internal database error").WithIsCertain(true).WithSendNotice(true)
	ErrTargetMessageNotFound           error = WrapErrorInStatus(errors.New("target message not found")).WithErrorAsMessage().WithIsCertain(true).WithSendNotice(false)
	ErrUnsupportedMessageType          error = WrapErrorInStatus(errors.New("unsupported message type")).WithErrorAsMessage().WithIsCertain(true).WithSendNotice(true)
	ErrMediaDownloadFailed             error = WrapErrorInStatus(errors.New("failed to download media")).WithMessage("failed to download media").WithIsCertain(true).WithSendNotice(true)
	ErrMediaReuploadFailed             error = WrapErrorInStatus(errors.New("failed to reupload media")).WithMessage("failed to reupload media").WithIsCertain(true).WithSendNotice(true)
	ErrMediaConvertFailed              error = WrapErrorInStatus(errors.New("failed to convert media")).WithMessage("failed to convert media").WithIsCertain(true).WithSendNotice(true)
	ErrMembershipNotSupported          error = WrapErrorInStatus(errors.New("this bridge does not support changing group membership")).WithIsCertain(true).WithErrorAsMessage().WithSendNotice(false)
)

type MessageStatusEventInfo struct {
	RoomID      id.RoomID
	EventID     id.EventID
	EventType   event.Type
	MessageType event.MessageType
	Sender      id.UserID
	ThreadRoot  id.EventID
}

func StatusEventInfoFromEvent(evt *event.Event) *MessageStatusEventInfo {
	var threadRoot id.EventID
	if relatable, ok := evt.Content.Parsed.(event.Relatable); ok {
		threadRoot = relatable.OptionalGetRelatesTo().GetThreadParent()
	}
	return &MessageStatusEventInfo{
		RoomID:      evt.RoomID,
		EventID:     evt.ID,
		EventType:   evt.Type,
		MessageType: evt.Content.AsMessage().MsgType,
		Sender:      evt.Sender,
		ThreadRoot:  threadRoot,
	}
}

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
		EventID:     evt.EventID,
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
			EventID: evt.EventID,
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
		MsgType:   event.MsgText,
		Body:      fmt.Sprintf("\u26a0\ufe0f %s: %s", messagePrefix, msg),
		RelatesTo: &event.RelatesTo{},
		Mentions:  &event.Mentions{},
	}
	if evt.ThreadRoot != "" {
		content.RelatesTo.SetThread(evt.ThreadRoot, evt.EventID)
	} else {
		content.RelatesTo.SetReplyTo(evt.EventID)
	}
	if evt.Sender != "" {
		content.Mentions.UserIDs = []id.UserID{evt.Sender}
	}
	return content
}
