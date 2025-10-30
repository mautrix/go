// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"errors"
	"fmt"
	"net/http"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

// ErrIgnoringRemoteEvent can be returned by [RemoteMessage.ConvertMessage] or [RemoteEdit.ConvertEdit]
// to indicate that the event should be ignored after all. Handling the event will be cancelled immediately.
var ErrIgnoringRemoteEvent = errors.New("ignoring remote event")

// ErrNoStatus can be returned by [MatrixMessageResponse.HandleEcho] to indicate that the message is still in-flight
// and a status should not be sent yet. The message will still be saved into the database.
var ErrNoStatus = errors.New("omit message status")

// ErrResolveIdentifierTryNext can be returned by ResolveIdentifier or CreateChatWithGhost to signal that
// the identifier is valid, but can't be reached by the current login, and the caller should try the next
// login if there are more.
//
// This should generally only be returned when resolving internal IDs (which happens when initiating chats via Matrix).
// For example, Google Messages would return this when trying to resolve another login's user ID,
// and Telegram would return this when the access hash isn't available.
var ErrResolveIdentifierTryNext = errors.New("that identifier is not available via this login")

var ErrNotLoggedIn = errors.New("not logged in")

// ErrDirectMediaNotEnabled may be returned by Matrix connectors if [MatrixConnector.GenerateContentURI] is called,
// but direct media is not enabled.
var ErrDirectMediaNotEnabled = errors.New("direct media is not enabled")

// Common message status errors
var (
	ErrPanicInEventHandler             error = WrapErrorInStatus(errors.New("panic in event handler")).WithSendNotice(true).WithErrorAsMessage()
	ErrNoPortal                        error = WrapErrorInStatus(errors.New("room is not a portal")).WithIsCertain(true).WithSendNotice(false)
	ErrIgnoringReactionFromRelayedUser error = WrapErrorInStatus(errors.New("ignoring reaction event from relayed user")).WithIsCertain(true).WithSendNotice(false)
	ErrIgnoringPollFromRelayedUser     error = WrapErrorInStatus(errors.New("ignoring poll event from relayed user")).WithIsCertain(true).WithSendNotice(false)
	ErrIgnoringDeleteChatRelayedUser   error = WrapErrorInStatus(errors.New("ignoring delete chat event from relayed user")).WithIsCertain(true).WithSendNotice(false)
	ErrEditsNotSupported               error = WrapErrorInStatus(errors.New("this bridge does not support edits")).WithIsCertain(true).WithErrorAsMessage().WithErrorReason(event.MessageStatusUnsupported)
	ErrEditsNotSupportedInPortal       error = WrapErrorInStatus(errors.New("edits are not allowed in this chat")).WithIsCertain(true).WithErrorAsMessage().WithErrorReason(event.MessageStatusUnsupported)
	ErrCaptionsNotAllowed              error = WrapErrorInStatus(errors.New("captions are not supported here")).WithIsCertain(true).WithErrorAsMessage().WithErrorReason(event.MessageStatusUnsupported)
	ErrLocationMessagesNotAllowed      error = WrapErrorInStatus(errors.New("location messages are not supported here")).WithIsCertain(true).WithErrorAsMessage().WithErrorReason(event.MessageStatusUnsupported)
	ErrEditTargetTooOld                error = WrapErrorInStatus(errors.New("the message is too old to be edited")).WithIsCertain(true).WithErrorAsMessage().WithErrorReason(event.MessageStatusUnsupported)
	ErrEditTargetTooManyEdits          error = WrapErrorInStatus(errors.New("the message has been edited too many times")).WithIsCertain(true).WithErrorAsMessage().WithErrorReason(event.MessageStatusUnsupported)
	ErrReactionsNotSupported           error = WrapErrorInStatus(errors.New("this bridge does not support reactions")).WithIsCertain(true).WithErrorAsMessage().WithErrorReason(event.MessageStatusUnsupported)
	ErrPollsNotSupported               error = WrapErrorInStatus(errors.New("this bridge does not support polls")).WithIsCertain(true).WithErrorAsMessage().WithErrorReason(event.MessageStatusUnsupported)
	ErrRoomMetadataNotSupported        error = WrapErrorInStatus(errors.New("this bridge does not support changing room metadata")).WithIsCertain(true).WithErrorAsMessage().WithSendNotice(false).WithErrorReason(event.MessageStatusUnsupported)
	ErrRoomMetadataNotAllowed          error = WrapErrorInStatus(errors.New("changes are not allowed here")).WithIsCertain(true).WithErrorAsMessage().WithSendNotice(false).WithErrorReason(event.MessageStatusUnsupported)
	ErrRedactionsNotSupported          error = WrapErrorInStatus(errors.New("this bridge does not support deleting messages")).WithIsCertain(true).WithErrorAsMessage().WithErrorReason(event.MessageStatusUnsupported)
	ErrUnexpectedParsedContentType     error = WrapErrorInStatus(errors.New("unexpected parsed content type")).WithErrorAsMessage().WithIsCertain(true).WithSendNotice(true)
	ErrInvalidStateKey                 error = WrapErrorInStatus(errors.New("room metadata state key is unset or non-empty")).WithErrorAsMessage().WithIsCertain(true).WithSendNotice(false)
	ErrDatabaseError                   error = WrapErrorInStatus(errors.New("database error")).WithMessage("internal database error").WithIsCertain(true).WithSendNotice(true)
	ErrTargetMessageNotFound           error = WrapErrorInStatus(errors.New("target message not found")).WithErrorAsMessage().WithIsCertain(true).WithSendNotice(false)
	ErrUnsupportedMessageType          error = WrapErrorInStatus(errors.New("unsupported message type")).WithErrorAsMessage().WithIsCertain(true).WithSendNotice(true).WithErrorReason(event.MessageStatusUnsupported)
	ErrUnsupportedMediaType            error = WrapErrorInStatus(errors.New("unsupported media type")).WithErrorAsMessage().WithIsCertain(true).WithSendNotice(true).WithErrorReason(event.MessageStatusUnsupported)
	ErrMediaDurationTooLong            error = WrapErrorInStatus(errors.New("media duration too long")).WithErrorAsMessage().WithSendNotice(true).WithErrorReason(event.MessageStatusUnsupported)
	ErrVoiceMessageDurationTooLong     error = WrapErrorInStatus(errors.New("voice message too long")).WithErrorAsMessage().WithSendNotice(true).WithErrorReason(event.MessageStatusUnsupported)
	ErrMediaTooLarge                   error = WrapErrorInStatus(errors.New("media too large")).WithErrorAsMessage().WithIsCertain(true).WithSendNotice(true).WithErrorReason(event.MessageStatusUnsupported)
	ErrIgnoringMNotice                 error = WrapErrorInStatus(errors.New("ignoring m.notice message")).WithIsCertain(true).WithErrorAsMessage().WithSendNotice(false)
	ErrMediaDownloadFailed             error = WrapErrorInStatus(errors.New("failed to download media")).WithMessage("failed to download media").WithIsCertain(true).WithSendNotice(true)
	ErrMediaReuploadFailed             error = WrapErrorInStatus(errors.New("failed to reupload media")).WithMessage("failed to reupload media").WithIsCertain(true).WithSendNotice(true)
	ErrMediaConvertFailed              error = WrapErrorInStatus(errors.New("failed to convert media")).WithMessage("failed to convert media").WithIsCertain(true).WithSendNotice(true)
	ErrMembershipNotSupported          error = WrapErrorInStatus(errors.New("this bridge does not support changing group membership")).WithIsCertain(true).WithErrorAsMessage().WithSendNotice(false).WithErrorReason(event.MessageStatusUnsupported)
	ErrDeleteChatNotSupported          error = WrapErrorInStatus(errors.New("this bridge does not support deleting chats")).WithIsCertain(true).WithErrorAsMessage().WithSendNotice(false).WithErrorReason(event.MessageStatusUnsupported)
	ErrPowerLevelsNotSupported         error = WrapErrorInStatus(errors.New("this bridge does not support changing group power levels")).WithIsCertain(true).WithErrorAsMessage().WithSendNotice(false).WithErrorReason(event.MessageStatusUnsupported)
	ErrRemoteEchoTimeout                     = WrapErrorInStatus(errors.New("remote echo timed out")).WithIsCertain(false).WithSendNotice(true).WithErrorReason(event.MessageStatusTooOld)
	ErrRemoteAckTimeout                      = WrapErrorInStatus(errors.New("remote ack timed out")).WithIsCertain(false).WithSendNotice(true).WithErrorReason(event.MessageStatusTooOld)

	ErrDisappearingTimerUnsupported error = WrapErrorInStatus(errors.New("invalid disappearing timer")).WithIsCertain(true)
)

// Common login interface errors
var (
	ErrInvalidLoginFlowID error = RespError(mautrix.MNotFound.WithMessage("Invalid login flow ID"))
)

// RespError is a class of error that certain network interface methods can return to ensure that the error
// is properly translated into an HTTP error when the method is called via the provisioning API.
//
// However, unlike mautrix.RespError, this does not include the error code
// in the message shown to users when used outside HTTP contexts.
type RespError mautrix.RespError

func (re RespError) Error() string {
	return re.Err
}

func (re RespError) Is(err error) bool {
	var e2 RespError
	if errors.As(err, &e2) {
		return e2.Err == re.Err
	}
	return errors.Is(err, mautrix.RespError(re))
}

func (re RespError) Write(w http.ResponseWriter) {
	mautrix.RespError(re).Write(w)
}

func (re RespError) WithMessage(msg string, args ...any) RespError {
	return RespError(mautrix.RespError(re).WithMessage(msg, args...))
}

func (re RespError) AppendMessage(append string, args ...any) RespError {
	re.Err += fmt.Sprintf(append, args...)
	return re
}

func WrapRespErrManual(err error, code string, status int) RespError {
	return RespError{ErrCode: code, Err: err.Error(), StatusCode: status}
}

func WrapRespErr(err error, target mautrix.RespError) RespError {
	return RespError{ErrCode: target.ErrCode, Err: err.Error(), StatusCode: target.StatusCode}
}
