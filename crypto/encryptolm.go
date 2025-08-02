// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"encoding/json"
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (mach *OlmMachine) EncryptToDevices(ctx context.Context, eventType event.Type, req *mautrix.ReqSendToDevice) (*mautrix.ReqSendToDevice, error) {
	devicesToCreateSessions := make(map[id.UserID]map[id.DeviceID]*id.Device)
	for userID, devices := range req.Messages {
		for deviceID := range devices {
			device, err := mach.GetOrFetchDevice(ctx, userID, deviceID)
			if err != nil {
				return nil, fmt.Errorf("failed to get device %s of user %s: %w", deviceID, userID, err)
			}

			if _, ok := devicesToCreateSessions[userID]; !ok {
				devicesToCreateSessions[userID] = make(map[id.DeviceID]*id.Device)
			}
			devicesToCreateSessions[userID][deviceID] = device
		}
	}
	if err := mach.createOutboundSessions(ctx, devicesToCreateSessions); err != nil {
		return nil, fmt.Errorf("failed to create outbound sessions: %w", err)
	}

	mach.olmLock.Lock()
	defer mach.olmLock.Unlock()

	encryptedReq := &mautrix.ReqSendToDevice{
		Messages: make(map[id.UserID]map[id.DeviceID]*event.Content),
	}

	log := mach.machOrContextLog(ctx)

	for userID, devices := range req.Messages {
		encryptedReq.Messages[userID] = make(map[id.DeviceID]*event.Content)

		for deviceID, content := range devices {
			device := devicesToCreateSessions[userID][deviceID]

			olmSess, err := mach.CryptoStore.GetLatestSession(ctx, device.IdentityKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get latest session for device %s of %s: %w", deviceID, userID, err)
			} else if olmSess == nil {
				log.Warn().
					Str("target_user_id", userID.String()).
					Str("target_device_id", deviceID.String()).
					Str("identity_key", device.IdentityKey.String()).
					Msg("No outbound session found for device")
				continue
			}

			encrypted := mach.encryptOlmEvent(ctx, olmSess, device, eventType, *content)
			encryptedContent := &event.Content{Parsed: &encrypted}

			log.Debug().
				Str("decrypted_type", eventType.Type).
				Str("target_user_id", userID.String()).
				Str("target_device_id", deviceID.String()).
				Str("target_identity_key", device.IdentityKey.String()).
				Str("olm_session_id", olmSess.ID().String()).
				Msg("Encrypted to-device event")

			encryptedReq.Messages[userID][deviceID] = encryptedContent
		}
	}

	return encryptedReq, nil
}

func (mach *OlmMachine) encryptOlmEvent(ctx context.Context, session *OlmSession, recipient *id.Device, evtType event.Type, content event.Content) *event.EncryptedEventContent {
	evt := &DecryptedOlmEvent{
		Sender:        mach.Client.UserID,
		SenderDevice:  mach.Client.DeviceID,
		Keys:          OlmEventKeys{Ed25519: mach.account.SigningKey()},
		Recipient:     recipient.UserID,
		RecipientKeys: OlmEventKeys{Ed25519: recipient.SigningKey},
		Type:          evtType,
		Content:       content,
	}
	plaintext, err := json.Marshal(evt)
	if err != nil {
		panic(err)
	}
	log := mach.machOrContextLog(ctx)
	log.Debug().
		Str("recipient_identity_key", recipient.IdentityKey.String()).
		Str("olm_session_id", session.ID().String()).
		Str("olm_session_description", session.Describe()).
		Msg("Encrypting olm message")
	msgType, ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}
	err = mach.CryptoStore.UpdateSession(ctx, recipient.IdentityKey, session)
	if err != nil {
		log.Error().Err(err).Msg("Failed to update olm session in crypto store after encrypting")
	}
	return &event.EncryptedEventContent{
		Algorithm: id.AlgorithmOlmV1,
		SenderKey: mach.account.IdentityKey(),
		OlmCiphertext: event.OlmCiphertexts{
			recipient.IdentityKey: {
				Type: msgType,
				Body: string(ciphertext),
			},
		},
	}
}

func (mach *OlmMachine) shouldCreateNewSession(ctx context.Context, identityKey id.IdentityKey) bool {
	if !mach.CryptoStore.HasSession(ctx, identityKey) {
		return true
	}
	mach.devicesToUnwedgeLock.Lock()
	_, shouldUnwedge := mach.devicesToUnwedge[identityKey]
	if shouldUnwedge {
		delete(mach.devicesToUnwedge, identityKey)
	}
	mach.devicesToUnwedgeLock.Unlock()
	return shouldUnwedge
}

func (mach *OlmMachine) createOutboundSessions(ctx context.Context, input map[id.UserID]map[id.DeviceID]*id.Device) error {
	request := make(mautrix.OneTimeKeysRequest)
	for userID, devices := range input {
		request[userID] = make(map[id.DeviceID]id.KeyAlgorithm)
		for deviceID, identity := range devices {
			if mach.shouldCreateNewSession(ctx, identity.IdentityKey) {
				request[userID][deviceID] = id.KeyAlgorithmSignedCurve25519
			}
		}
		if len(request[userID]) == 0 {
			delete(request, userID)
		}
	}
	if len(request) == 0 {
		return nil
	}
	resp, err := mach.Client.ClaimKeys(ctx, &mautrix.ReqClaimKeys{
		OneTimeKeys: request,
		Timeout:     10 * 1000,
	})
	if err != nil {
		return fmt.Errorf("failed to claim keys: %w", err)
	}
	log := mach.machOrContextLog(ctx)
	for userID, user := range resp.OneTimeKeys {
		for deviceID, oneTimeKeys := range user {
			var oneTimeKey mautrix.OneTimeKey
			var keyID id.KeyID
			for keyID, oneTimeKey = range oneTimeKeys {
				break
			}
			log := log.With().
				Str("peer_user_id", userID.String()).
				Str("peer_device_id", deviceID.String()).
				Str("peer_otk_id", keyID.String()).
				Logger()
			keyAlg, _ := keyID.Parse()
			if keyAlg != id.KeyAlgorithmSignedCurve25519 {
				log.Warn().Msg("Unexpected key ID algorithm in one-time key response")
				continue
			}
			identity := input[userID][deviceID]
			if ok, err := signatures.VerifySignatureJSON(oneTimeKey.RawData, userID, deviceID.String(), identity.SigningKey); err != nil {
				log.Error().Err(err).Msg("Failed to verify signature of one-time key")
			} else if !ok {
				log.Warn().Msg("One-time key has invalid signature from device")
			} else if sess, err := mach.account.InternalLibolm.NewOutboundSession(identity.IdentityKey, oneTimeKey.Key); err != nil {
				log.Error().Err(err).Msg("Failed to create outbound session with claimed one-time key")
			} else {
				goolmSess, err := mach.account.InternalGoolm.NewOutboundSession(identity.IdentityKey, oneTimeKey.Key)
				if err != nil {
					panic("goolm NewOutboundSession errored")
				}
				if sess.Describe() != goolmSess.Describe() {
					panic("goolm NewOutboundSession and libolm NewOutboundSession returned different values")
				}

				wrapped := wrapSession(sess)
				err = mach.CryptoStore.AddSession(ctx, identity.IdentityKey, wrapped)
				if err != nil {
					log.Error().Err(err).Msg("Failed to store created outbound session")
				} else {
					log.Debug().Msg("Created new Olm session")
				}
			}
		}
	}
	return nil
}
