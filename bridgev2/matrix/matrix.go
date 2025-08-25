// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"

	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (br *Connector) handleRoomEvent(ctx context.Context, evt *event.Event) {
	if br.shouldIgnoreEvent(evt) {
		return
	}
	if (evt.Type == event.EventMessage || evt.Type == event.EventSticker) && !evt.Mautrix.WasEncrypted && br.Config.Encryption.Require {
		zerolog.Ctx(ctx).Warn().Msg("Dropping unencrypted event as encryption is configured to be required")
		br.sendCryptoStatusError(ctx, evt, errMessageNotEncrypted, nil, 0, true)
		return
	}
	if evt.Type == event.StateMember && br.Crypto != nil {
		br.Crypto.HandleMemberEvent(ctx, evt)
	}
	br.Bridge.QueueMatrixEvent(ctx, evt)
}

func (br *Connector) handleEphemeralEvent(ctx context.Context, evt *event.Event) {
	switch evt.Type {
	case event.EphemeralEventReceipt:
		receiptContent := *evt.Content.AsReceipt()
		for eventID, receipts := range receiptContent {
			for receiptType, userReceipts := range receipts {
				for userID, receipt := range userReceipts {
					if br.shouldIgnoreEventFromUser(userID) || (br.AS.DoublePuppetValue != "" && receipt.Extra[appservice.DoublePuppetKey] == br.AS.DoublePuppetValue) {
						delete(userReceipts, userID)
					}
				}
				if len(userReceipts) == 0 {
					delete(receipts, receiptType)
				}
			}
			if len(receipts) == 0 {
				delete(receiptContent, eventID)
			}
		}
		if len(receiptContent) == 0 {
			return
		}
	case event.EphemeralEventTyping:
		typingContent := evt.Content.AsTyping()
		typingContent.UserIDs = slices.DeleteFunc(typingContent.UserIDs, br.shouldIgnoreEventFromUser)
	}
	br.Bridge.QueueMatrixEvent(ctx, evt)
}

func (br *Connector) handleEncryptedEvent(ctx context.Context, evt *event.Event) {
	if br.shouldIgnoreEvent(evt) {
		return
	}
	content := evt.Content.AsEncrypted()
	log := zerolog.Ctx(ctx).With().
		Str("event_id", evt.ID.String()).
		Str("session_id", content.SessionID.String()).
		Logger()
	ctx = log.WithContext(ctx)
	if br.Crypto == nil {
		br.sendCryptoStatusError(ctx, evt, errNoCrypto, nil, 0, true)
		log.Error().Msg("Can't decrypt message: no crypto")
		return
	}
	log.Debug().Msg("Decrypting received event")

	decryptionStart := time.Now()
	decrypted, err := br.Crypto.Decrypt(ctx, evt)
	decryptionRetryCount := 0
	var errorEventID id.EventID
	if errors.Is(err, NoSessionFound) {
		decryptionRetryCount = 1
		log.Debug().
			Int("wait_seconds", int(initialSessionWaitTimeout.Seconds())).
			Msg("Couldn't find session, waiting for keys to arrive...")
		go br.sendCryptoStatusError(ctx, evt, err, &errorEventID, 0, false)
		if br.Crypto.WaitForSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, initialSessionWaitTimeout) {
			log.Debug().Msg("Got keys after waiting, trying to decrypt event again")
			decrypted, err = br.Crypto.Decrypt(ctx, evt)
		} else {
			go br.waitLongerForSession(ctx, evt, decryptionStart, &errorEventID)
			return
		}
	}
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt event")
		go br.sendCryptoStatusError(ctx, evt, err, nil, decryptionRetryCount, true)
		return
	}
	br.postDecrypt(ctx, evt, decrypted, decryptionRetryCount, &errorEventID, time.Since(decryptionStart))
}

func (br *Connector) waitLongerForSession(ctx context.Context, evt *event.Event, decryptionStart time.Time, errorEventID *id.EventID) {
	log := zerolog.Ctx(ctx)
	content := evt.Content.AsEncrypted()
	log.Debug().
		Int("wait_seconds", int(extendedSessionWaitTimeout.Seconds())).
		Msg("Couldn't find session, requesting keys and waiting longer...")

	go br.Crypto.RequestSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, evt.Sender, content.DeviceID)
	go br.sendCryptoStatusError(ctx, evt, fmt.Errorf("%w. The bridge will retry for %d seconds", errNoDecryptionKeys, int(extendedSessionWaitTimeout.Seconds())), errorEventID, 1, false)

	if !br.Crypto.WaitForSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, extendedSessionWaitTimeout) {
		log.Debug().Msg("Didn't get session, giving up trying to decrypt event")
		go br.sendCryptoStatusError(ctx, evt, errNoDecryptionKeys, errorEventID, 2, true)
		return
	}

	log.Debug().Msg("Got keys after waiting longer, trying to decrypt event again")
	decrypted, err := br.Crypto.Decrypt(ctx, evt)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt event")
		go br.sendCryptoStatusError(ctx, evt, err, errorEventID, 2, true)
		return
	}

	br.postDecrypt(ctx, evt, decrypted, 2, errorEventID, time.Since(decryptionStart))
}

type CommandProcessor interface {
	Handle(ctx context.Context, roomID id.RoomID, eventID id.EventID, user bridgev2.User, message string, replyTo id.EventID)
}

func (br *Connector) sendSuccessCheckpoint(ctx context.Context, evt *event.Event, step status.MessageCheckpointStep, retryNum int) {
	err := br.SendMessageCheckpoints(ctx, []*status.MessageCheckpoint{{
		RoomID:      evt.RoomID,
		EventID:     evt.ID,
		EventType:   evt.Type,
		MessageType: evt.Content.AsMessage().MsgType,
		Step:        step,
		Timestamp:   jsontime.UnixMilliNow(),
		Status:      status.MsgStatusSuccess,
		ReportedBy:  status.MsgReportedByBridge,
		RetryNum:    retryNum,
	}})
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Str("checkpoint_step", string(step)).Msg("Failed to send checkpoint")
	}
}

func (br *Connector) sendBridgeCheckpoint(ctx context.Context, evt *event.Event) {
	if !evt.Mautrix.CheckpointSent {
		go br.sendSuccessCheckpoint(ctx, evt, status.MsgStepBridge, 0)
	}
}

func (br *Connector) shouldIgnoreEventFromUser(userID id.UserID) bool {
	return userID == br.Bot.UserID || br.Bridge.IsGhostMXID(userID)
}

func (br *Connector) shouldIgnoreEvent(evt *event.Event) bool {
	if br.shouldIgnoreEventFromUser(evt.Sender) && evt.Type != event.StateTombstone {
		return true
	}
	dpVal, ok := evt.Content.Raw[appservice.DoublePuppetKey]
	if ok && dpVal == br.AS.DoublePuppetValue {
		dpTS, ok := evt.Content.Raw[appservice.DoublePuppetTSKey].(float64)
		if !ok || int64(dpTS) == evt.Timestamp {
			return true
		}
	}
	return false
}

const initialSessionWaitTimeout = 3 * time.Second
const extendedSessionWaitTimeout = 22 * time.Second

func copySomeKeys(original, decrypted *event.Event) {
	isScheduled, _ := original.Content.Raw["com.beeper.scheduled"].(bool)
	_, alreadyExists := decrypted.Content.Raw["com.beeper.scheduled"]
	if isScheduled && !alreadyExists {
		decrypted.Content.Raw["com.beeper.scheduled"] = true
	}
}

func (br *Connector) postDecrypt(ctx context.Context, original, decrypted *event.Event, retryCount int, errorEventID *id.EventID, duration time.Duration) {
	log := zerolog.Ctx(ctx)
	minLevel := br.Config.Encryption.VerificationLevels.Send
	if decrypted.Mautrix.TrustState < minLevel {
		logEvt := log.Warn().
			Str("user_id", decrypted.Sender.String()).
			Bool("forwarded_keys", decrypted.Mautrix.ForwardedKeys).
			Stringer("device_trust", decrypted.Mautrix.TrustState).
			Stringer("min_trust", minLevel)
		if decrypted.Mautrix.TrustSource != nil {
			dev := decrypted.Mautrix.TrustSource
			logEvt.
				Str("device_id", dev.DeviceID.String()).
				Str("device_signing_key", dev.SigningKey.String())
		} else {
			logEvt.Str("device_id", "unknown")
		}
		logEvt.Msg("Dropping event due to insufficient verification level")
		err := deviceUnverifiedErrorWithExplanation(decrypted.Mautrix.TrustState)
		go br.sendCryptoStatusError(ctx, decrypted, err, errorEventID, retryCount, true)
		return
	}
	copySomeKeys(original, decrypted)

	go br.sendSuccessCheckpoint(ctx, decrypted, status.MsgStepDecrypted, retryCount)
	decrypted.Mautrix.CheckpointSent = true
	decrypted.Mautrix.DecryptionDuration = duration
	decrypted.Mautrix.EventSource |= event.SourceDecrypted
	br.EventProcessor.Dispatch(ctx, decrypted)
	if errorEventID != nil && *errorEventID != "" {
		_, _ = br.Bot.RedactEvent(ctx, decrypted.RoomID, *errorEventID)
	}
}
