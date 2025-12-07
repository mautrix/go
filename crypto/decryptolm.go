// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix/crypto/goolm/account"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	ErrUnsupportedAlgorithm                = errors.New("unsupported event encryption algorithm")
	ErrNotEncryptedForMe                   = errors.New("olm event doesn't contain ciphertext for this device")
	ErrUnsupportedOlmMessageType           = errors.New("unsupported olm message type")
	ErrDecryptionFailedWithMatchingSession = errors.New("decryption failed with matching session")
	ErrDecryptionFailedForNormalMessage    = errors.New("decryption failed for normal message")
	ErrSenderMismatch                      = errors.New("mismatched sender in olm payload")
	ErrRecipientMismatch                   = errors.New("mismatched recipient in olm payload")
	ErrRecipientKeyMismatch                = errors.New("mismatched recipient key in olm payload")
	ErrDuplicateMessage                    = errors.New("duplicate olm message")
)

// Deprecated: use variables prefixed with Err
var (
	UnsupportedAlgorithm                = ErrUnsupportedAlgorithm
	NotEncryptedForMe                   = ErrNotEncryptedForMe
	UnsupportedOlmMessageType           = ErrUnsupportedOlmMessageType
	DecryptionFailedWithMatchingSession = ErrDecryptionFailedWithMatchingSession
	DecryptionFailedForNormalMessage    = ErrDecryptionFailedForNormalMessage
	SenderMismatch                      = ErrSenderMismatch
	RecipientMismatch                   = ErrRecipientMismatch
	RecipientKeyMismatch                = ErrRecipientKeyMismatch
)

// DecryptedOlmEvent represents an event that was decrypted from an event encrypted with the m.olm.v1.curve25519-aes-sha2 algorithm.
type DecryptedOlmEvent struct {
	Source *event.Event `json:"-"`

	SenderKey id.SenderKey `json:"-"`

	Sender        id.UserID    `json:"sender"`
	SenderDevice  id.DeviceID  `json:"sender_device"`
	Keys          OlmEventKeys `json:"keys"`
	Recipient     id.UserID    `json:"recipient"`
	RecipientKeys OlmEventKeys `json:"recipient_keys"`

	Type    event.Type    `json:"type"`
	Content event.Content `json:"content"`
}

func (mach *OlmMachine) decryptOlmEvent(ctx context.Context, evt *event.Event) (*DecryptedOlmEvent, error) {
	content, ok := evt.Content.Parsed.(*event.EncryptedEventContent)
	if !ok {
		return nil, ErrIncorrectEncryptedContentType
	} else if content.Algorithm != id.AlgorithmOlmV1 {
		return nil, ErrUnsupportedAlgorithm
	}
	ownContent, ok := content.OlmCiphertext[mach.account.IdentityKey()]
	if !ok {
		return nil, ErrNotEncryptedForMe
	}
	decrypted, err := mach.decryptAndParseOlmCiphertext(ctx, evt, content.SenderKey, ownContent.Type, ownContent.Body)
	if err != nil {
		return nil, err
	}
	decrypted.Source = evt
	return decrypted, nil
}

type OlmEventKeys struct {
	Ed25519 id.Ed25519 `json:"ed25519"`
}

func (mach *OlmMachine) decryptAndParseOlmCiphertext(ctx context.Context, evt *event.Event, senderKey id.SenderKey, olmType id.OlmMsgType, ciphertext string) (*DecryptedOlmEvent, error) {
	if olmType != id.OlmMsgTypePreKey && olmType != id.OlmMsgTypeMsg {
		return nil, ErrUnsupportedOlmMessageType
	}

	log := mach.machOrContextLog(ctx).With().
		Stringer("sender_key", senderKey).
		Int("olm_msg_type", int(olmType)).
		Logger()
	ctx = log.WithContext(ctx)
	endTimeTrace := mach.timeTrace(ctx, "decrypting olm ciphertext", 5*time.Second)
	plaintext, err := mach.tryDecryptOlmCiphertext(ctx, evt.Sender, senderKey, olmType, ciphertext)
	endTimeTrace()
	if err != nil {
		return nil, err
	}

	defer mach.timeTrace(ctx, "parsing decrypted olm event", time.Second)()

	var olmEvt DecryptedOlmEvent
	err = json.Unmarshal(plaintext, &olmEvt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse olm payload: %w", err)
	}
	olmEvt.Type.Class = evt.Type.Class
	if evt.Sender != olmEvt.Sender {
		return nil, ErrSenderMismatch
	} else if mach.Client.UserID != olmEvt.Recipient {
		return nil, ErrRecipientMismatch
	} else if mach.account.SigningKey() != olmEvt.RecipientKeys.Ed25519 {
		return nil, ErrRecipientKeyMismatch
	}

	if len(olmEvt.Content.VeryRaw) > 0 {
		err = olmEvt.Content.ParseRaw(olmEvt.Type)
		if err != nil && !errors.Is(err, event.ErrUnsupportedContentType) {
			return nil, fmt.Errorf("failed to parse content of olm payload event: %w", err)
		}
	}

	olmEvt.SenderKey = senderKey

	return &olmEvt, nil
}

func olmMessageHash(ciphertext string) ([32]byte, error) {
	ciphertextBytes, err := base64.RawStdEncoding.DecodeString(ciphertext)
	return sha256.Sum256(ciphertextBytes), err
}

func (mach *OlmMachine) tryDecryptOlmCiphertext(ctx context.Context, sender id.UserID, senderKey id.SenderKey, olmType id.OlmMsgType, ciphertext string) ([]byte, error) {
	ciphertextHash, err := olmMessageHash(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to hash olm ciphertext: %w", err)
	}

	log := *zerolog.Ctx(ctx)
	endTimeTrace := mach.timeTrace(ctx, "waiting for olm lock", 5*time.Second)
	mach.olmLock.Lock()
	endTimeTrace()
	defer mach.olmLock.Unlock()

	duplicateTS, err := mach.CryptoStore.GetOlmHash(ctx, ciphertextHash)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to check for duplicate olm message")
	} else if !duplicateTS.IsZero() {
		log.Warn().
			Hex("ciphertext_hash", ciphertextHash[:]).
			Time("duplicate_ts", duplicateTS).
			Msg("Ignoring duplicate olm message")
		return nil, ErrDuplicateMessage
	}

	plaintext, err := mach.tryDecryptOlmCiphertextWithExistingSession(ctx, senderKey, olmType, ciphertext, ciphertextHash)
	if err != nil {
		if err == ErrDecryptionFailedWithMatchingSession {
			log.Warn().Msg("Found matching session, but decryption failed")
			go mach.unwedgeDevice(log, sender, senderKey)
		}
		return nil, fmt.Errorf("failed to decrypt olm event: %w", err)
	}

	if plaintext != nil {
		// Decryption successful
		return plaintext, nil
	}

	// Decryption failed with every known session or no known sessions, let's try to create a new session.
	//
	// New sessions can only be created if it's a prekey message, we can't decrypt the message
	// if it isn't one at this point in time anymore, so return early.
	if olmType != id.OlmMsgTypePreKey {
		go mach.unwedgeDevice(log, sender, senderKey)
		return nil, ErrDecryptionFailedForNormalMessage
	}

	accountBackup, _ := mach.account.Internal.Pickle([]byte("tmp"))
	log.Trace().Msg("Trying to create inbound session")
	endTimeTrace = mach.timeTrace(ctx, "creating inbound olm session", time.Second)
	session, err := mach.createInboundSession(ctx, senderKey, ciphertext)
	endTimeTrace()
	if err != nil {
		go mach.unwedgeDevice(log, sender, senderKey)
		return nil, fmt.Errorf("failed to create new session from prekey message: %w", err)
	}
	log = log.With().Str("new_olm_session_id", session.ID().String()).Logger()
	log.Debug().
		Hex("ciphertext_hash", ciphertextHash[:]).
		Hex("ciphertext_hash_repeat", ptr.Ptr(exerrors.Must(olmMessageHash(ciphertext)))[:]).
		Str("olm_session_description", session.Describe()).
		Msg("Created inbound olm session")
	ctx = log.WithContext(ctx)

	endTimeTrace = mach.timeTrace(ctx, "decrypting prekey olm message", time.Second)
	plaintext, err = session.Decrypt(ciphertext, olmType)
	endTimeTrace()
	if err != nil {
		log.Debug().
			Hex("ciphertext_hash", ciphertextHash[:]).
			Hex("ciphertext_hash_repeat", ptr.Ptr(exerrors.Must(olmMessageHash(ciphertext)))[:]).
			Str("ciphertext", ciphertext).
			Str("olm_session_description", session.Describe()).
			Msg("DEBUG: Failed to decrypt prekey olm message with newly created session")
		err2 := mach.goolmRetryHack(ctx, senderKey, ciphertext, accountBackup)
		if err2 != nil {
			log.Debug().Err(err2).Msg("Goolm confirmed decryption failure")
		} else {
			log.Warn().Msg("Goolm decryption was successful after libolm failure?")
		}

		go mach.unwedgeDevice(log, sender, senderKey)
		return nil, fmt.Errorf("failed to decrypt olm event with session created from prekey message: %w", err)
	}

	endTimeTrace = mach.timeTrace(ctx, "updating new session in database", time.Second)
	err = mach.CryptoStore.PutOlmHash(ctx, ciphertextHash, time.Now())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to store olm message hash after decrypting")
	}
	err = mach.CryptoStore.UpdateSession(ctx, senderKey, session)
	endTimeTrace()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to update new olm session in crypto store after decrypting")
	}
	return plaintext, nil
}

func (mach *OlmMachine) goolmRetryHack(ctx context.Context, senderKey id.SenderKey, ciphertext string, accountBackup []byte) error {
	acc, err := account.AccountFromPickled(accountBackup, []byte("tmp"))
	if err != nil {
		return fmt.Errorf("failed to unpickle olm account: %w", err)
	}
	sess, err := acc.NewInboundSessionFrom(&senderKey, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to create inbound session: %w", err)
	}
	_, err = sess.Decrypt(ciphertext, id.OlmMsgTypePreKey)
	if err != nil {
		// This is the expected result if libolm failed
		return fmt.Errorf("failed to decrypt with new session: %w", err)
	}
	return nil
}

const MaxOlmSessionsPerDevice = 5

func (mach *OlmMachine) tryDecryptOlmCiphertextWithExistingSession(
	ctx context.Context, senderKey id.SenderKey, olmType id.OlmMsgType, ciphertext string, ciphertextHash [32]byte,
) ([]byte, error) {
	log := *zerolog.Ctx(ctx)
	endTimeTrace := mach.timeTrace(ctx, "getting sessions with sender key", time.Second)
	sessions, err := mach.CryptoStore.GetSessions(ctx, senderKey)
	endTimeTrace()
	if err != nil {
		return nil, fmt.Errorf("failed to get session for %s: %w", senderKey, err)
	}
	if len(sessions) > MaxOlmSessionsPerDevice*2 {
		// SQL store sorts sessions, but other implementations may not, so re-sort just in case
		slices.SortFunc(sessions, func(a, b *OlmSession) int {
			return b.LastDecryptedTime.Compare(a.LastDecryptedTime)
		})
		log.Warn().
			Int("session_count", len(sessions)).
			Time("newest_last_decrypted_at", sessions[0].LastDecryptedTime).
			Time("oldest_last_decrypted_at", sessions[len(sessions)-1].LastDecryptedTime).
			Msg("Too many sessions, deleting old ones")
		for i := MaxOlmSessionsPerDevice; i < len(sessions); i++ {
			err = mach.CryptoStore.DeleteSession(ctx, senderKey, sessions[i])
			if err != nil {
				log.Warn().Err(err).
					Stringer("olm_session_id", sessions[i].ID()).
					Time("last_decrypt", sessions[i].LastDecryptedTime).
					Msg("Failed to delete olm session")
			} else {
				log.Debug().
					Stringer("olm_session_id", sessions[i].ID()).
					Time("last_decrypt", sessions[i].LastDecryptedTime).
					Msg("Deleted olm session")
			}
		}
		sessions = sessions[:MaxOlmSessionsPerDevice]
	}

	for _, session := range sessions {
		log := log.With().Str("olm_session_id", session.ID().String()).Logger()
		ctx := log.WithContext(ctx)
		if olmType == id.OlmMsgTypePreKey {
			endTimeTrace = mach.timeTrace(ctx, "checking if prekey olm message matches session", time.Second)
			matches, err := session.Internal.MatchesInboundSession(ciphertext)
			endTimeTrace()
			if err != nil {
				return nil, fmt.Errorf("failed to check if ciphertext matches inbound session: %w", err)
			} else if !matches {
				continue
			}
		}
		endTimeTrace = mach.timeTrace(ctx, "decrypting olm message", time.Second)
		plaintext, err := session.Decrypt(ciphertext, olmType)
		endTimeTrace()
		if err != nil {
			log.Warn().Err(err).
				Hex("ciphertext_hash", ciphertextHash[:]).
				Hex("ciphertext_hash_repeat", ptr.Ptr(exerrors.Must(olmMessageHash(ciphertext)))[:]).
				Str("session_description", session.Describe()).
				Msg("Failed to decrypt olm message")
			if olmType == id.OlmMsgTypePreKey {
				return nil, ErrDecryptionFailedWithMatchingSession
			}
		} else {
			endTimeTrace = mach.timeTrace(ctx, "updating session in database", time.Second)
			err = mach.CryptoStore.PutOlmHash(ctx, ciphertextHash, time.Now())
			if err != nil {
				log.Warn().Err(err).Msg("Failed to store olm message hash after decrypting")
			}
			err = mach.CryptoStore.UpdateSession(ctx, senderKey, session)
			endTimeTrace()
			if err != nil {
				log.Warn().Err(err).Msg("Failed to update olm session in crypto store after decrypting")
			}
			log.Debug().
				Hex("ciphertext_hash", ciphertextHash[:]).
				Str("session_description", session.Describe()).
				Msg("Decrypted olm message")
			return plaintext, nil
		}
	}
	return nil, nil
}

func (mach *OlmMachine) createInboundSession(ctx context.Context, senderKey id.SenderKey, ciphertext string) (*OlmSession, error) {
	session, err := mach.account.NewInboundSessionFrom(senderKey, ciphertext)
	if err != nil {
		return nil, err
	}
	mach.saveAccount(ctx)
	err = mach.CryptoStore.AddSession(ctx, senderKey, session)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Msg("Failed to store created inbound session")
	}
	return session, nil
}

const MinUnwedgeInterval = 1 * time.Hour

func (mach *OlmMachine) unwedgeDevice(log zerolog.Logger, sender id.UserID, senderKey id.SenderKey) {
	log = log.With().Str("action", "unwedge olm session").Logger()
	ctx := log.WithContext(mach.backgroundCtx)
	mach.recentlyUnwedgedLock.Lock()
	prevUnwedge, ok := mach.recentlyUnwedged[senderKey]
	delta := time.Since(prevUnwedge)
	if ok && delta < MinUnwedgeInterval {
		log.Debug().
			Str("previous_recreation", delta.String()).
			Msg("Not creating new Olm session as it was already recreated recently")
		mach.recentlyUnwedgedLock.Unlock()
		return
	}
	mach.recentlyUnwedged[senderKey] = time.Now()
	mach.recentlyUnwedgedLock.Unlock()

	lastCreatedAt, err := mach.CryptoStore.GetNewestSessionCreationTS(ctx, senderKey)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get newest session creation timestamp")
		return
	} else if time.Since(lastCreatedAt) < MinUnwedgeInterval {
		log.Debug().
			Time("last_created_at", lastCreatedAt).
			Msg("Not creating new Olm session as it was already recreated recently")
		return
	}

	deviceIdentity, err := mach.GetOrFetchDeviceByKey(ctx, sender, senderKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to find device info by identity key")
		return
	} else if deviceIdentity == nil {
		log.Warn().Msg("Didn't find identity for device")
		return
	}

	log.Debug().
		Time("last_created", lastCreatedAt).
		Stringer("device_id", deviceIdentity.DeviceID).
		Msg("Creating new Olm session")
	mach.devicesToUnwedgeLock.Lock()
	mach.devicesToUnwedge[senderKey] = true
	mach.devicesToUnwedgeLock.Unlock()
	err = mach.SendEncryptedToDevice(ctx, deviceIdentity, event.ToDeviceDummy, event.Content{})
	if err != nil {
		log.Error().Err(err).Msg("Failed to send dummy event to unwedge session")
	}
}
