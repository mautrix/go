// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"errors"
	"fmt"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	errDeviceNotTrusted    = errors.New("your device is not trusted")
	errMessageNotEncrypted = errors.New("unencrypted message")
	errNoDecryptionKeys    = errors.New("the bridge hasn't received the decryption keys")
	errNoCrypto            = errors.New("this bridge has not been configured to support encryption")
)

func errorToHumanMessage(err error) string {
	var withheld *event.RoomKeyWithheldEventContent
	switch {
	case errors.Is(err, errDeviceNotTrusted), errors.Is(err, errNoDecryptionKeys), errors.Is(err, errNoCrypto):
		return err.Error()
	case errors.Is(err, UnknownMessageIndex):
		return "the keys received by the bridge can't decrypt the message"
	case errors.Is(err, DuplicateMessageIndex):
		return "your client encrypted multiple messages with the same key"
	case errors.As(err, &withheld):
		if withheld.Code == event.RoomKeyWithheldBeeperRedacted {
			return "your client used an outdated encryption session"
		}
		return "your client refused to share decryption keys with the bridge"
	case errors.Is(err, errMessageNotEncrypted):
		return "the message is not encrypted"
	default:
		return "the bridge failed to decrypt the message"
	}
}

func deviceUnverifiedErrorWithExplanation(trust id.TrustState) error {
	var explanation string
	switch trust {
	case id.TrustStateBlacklisted:
		explanation = "device is blacklisted"
	case id.TrustStateUnset:
		explanation = "unverified"
	case id.TrustStateUnknownDevice:
		explanation = "device info not found"
	case id.TrustStateForwarded:
		explanation = "keys were forwarded from an unknown device"
	case id.TrustStateCrossSignedUntrusted:
		explanation = "cross-signing keys changed after setting up the bridge"
	default:
		return errDeviceNotTrusted
	}
	return fmt.Errorf("%w (%s)", errDeviceNotTrusted, explanation)
}

func (br *Connector) sendCryptoStatusError(ctx context.Context, evt *event.Event, err error, errorEventID *id.EventID, retryNum int, isFinal bool) {
	ms := &bridgev2.MessageStatus{
		Step:          status.MsgStepDecrypted,
		Status:        event.MessageStatusRetriable,
		ErrorReason:   event.MessageStatusUndecryptable,
		InternalError: err,
		Message:       errorToHumanMessage(err),
		IsCertain:     true,
		SendNotice:    true,
		RetryNum:      retryNum,
	}
	if !isFinal {
		ms.Status = event.MessageStatusPending
		// Don't send notice for first error
		if retryNum == 0 {
			ms.SendNotice = false
			ms.DisableMSS = true
		}
	}
	var editEventID id.EventID
	if errorEventID != nil {
		editEventID = *errorEventID
	}
	respEventID := br.internalSendMessageStatus(ctx, ms, bridgev2.StatusEventInfoFromEvent(evt), editEventID)
	if errorEventID != nil && *errorEventID == "" {
		*errorEventID = respEventID
	}
}
