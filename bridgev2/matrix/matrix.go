// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (br *Connector) handleRoomEvent(ctx context.Context, evt *event.Event) {
	if br.shouldIgnoreEvent(evt) {
		return
	}
	if (evt.Type == event.EventMessage || evt.Type == event.EventSticker) && !evt.Mautrix.WasEncrypted && br.Config.Encryption.Require {
		zerolog.Ctx(ctx).Warn().Msg("Dropping unencrypted event as encryption is configured to be required")
		// TODO send metrics
		return
	}
	br.Bridge.QueueMatrixEvent(ctx, evt)
}

func (br *Connector) handleEphemeralEvent(ctx context.Context, evt *event.Event) {
	if br.shouldIgnoreEvent(evt) {
		return
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
		// TODO send metrics
		log.Error().Msg("Can't decrypt message: no crypto")
		return
	}
	log.Debug().Msg("Decrypting received event")

	decryptionStart := time.Now()
	decrypted, err := br.Crypto.Decrypt(ctx, evt)
	decryptionRetryCount := 0
	if errors.Is(err, NoSessionFound) {
		decryptionRetryCount = 1
		log.Debug().
			Int("wait_seconds", int(initialSessionWaitTimeout.Seconds())).
			Msg("Couldn't find session, waiting for keys to arrive...")
		// TODO send metrics
		if br.Crypto.WaitForSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, initialSessionWaitTimeout) {
			log.Debug().Msg("Got keys after waiting, trying to decrypt event again")
			decrypted, err = br.Crypto.Decrypt(ctx, evt)
		} else {
			go br.waitLongerForSession(ctx, evt, decryptionStart)
			return
		}
	}
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt event")
		// TODO send metrics
		return
	}
	br.postDecrypt(ctx, evt, decrypted, decryptionRetryCount, "", time.Since(decryptionStart))
}

func (br *Connector) waitLongerForSession(ctx context.Context, evt *event.Event, decryptionStart time.Time) {
	log := zerolog.Ctx(ctx)
	content := evt.Content.AsEncrypted()
	log.Debug().
		Int("wait_seconds", int(extendedSessionWaitTimeout.Seconds())).
		Msg("Couldn't find session, requesting keys and waiting longer...")

	go br.Crypto.RequestSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, evt.Sender, content.DeviceID)
	var errorEventID id.EventID
	// TODO send metrics

	if !br.Crypto.WaitForSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, extendedSessionWaitTimeout) {
		log.Debug().Msg("Didn't get session, giving up trying to decrypt event")
		// TODO send metrics
		return
	}

	log.Debug().Msg("Got keys after waiting longer, trying to decrypt event again")
	decrypted, err := br.Crypto.Decrypt(ctx, evt)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt event")
		// TODO send metrics
		return
	}

	br.postDecrypt(ctx, evt, decrypted, 2, errorEventID, time.Since(decryptionStart))
}

type CommandProcessor interface {
	Handle(ctx context.Context, roomID id.RoomID, eventID id.EventID, user bridgev2.User, message string, replyTo id.EventID)
}

func (br *Connector) sendBridgeCheckpoint(_ context.Context, evt *event.Event) {
	if !evt.Mautrix.CheckpointSent {
		//go br.SendMessageSuccessCheckpoint(evt, status.MsgStepBridge, 0)
	}
}

func (br *Connector) shouldIgnoreEvent(evt *event.Event) bool {
	if evt.Sender == br.Bot.UserID {
		return true
	}
	_, isGhost := br.ParseGhostMXID(evt.Sender)
	if isGhost {
		return true
	}
	// TODO exclude double puppeted events
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

func (br *Connector) postDecrypt(ctx context.Context, original, decrypted *event.Event, retryCount int, errorEventID id.EventID, duration time.Duration) {
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
		//err := deviceUnverifiedErrorWithExplanation(decrypted.Mautrix.TrustState)
		//go mx.sendCryptoStatusError(ctx, decrypted, errorEventID, err, retryCount, true)
		return
	}
	copySomeKeys(original, decrypted)

	// TODO checkpoint
	decrypted.Mautrix.CheckpointSent = true
	decrypted.Mautrix.DecryptionDuration = duration
	decrypted.Mautrix.EventSource |= event.SourceDecrypted
	br.EventProcessor.Dispatch(ctx, decrypted)
	if errorEventID != "" {
		_, _ = br.Bot.RedactEvent(ctx, decrypted.RoomID, errorEventID)
	}
}
