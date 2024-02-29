// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"time"

	"go.mau.fi/util/random"

	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
)

func (mach *OlmMachine) GetOrRequestSecret(ctx context.Context, name id.Secret, timeout time.Duration) (secret string, err error) {
	secret, err = mach.CryptoStore.GetSecret(ctx, name)
	if err != nil || secret != "" {
		return
	}

	requestID, secretChan := random.String(64), make(chan string, 1)
	mach.secretLock.Lock()
	mach.secretListeners[requestID] = secretChan
	mach.secretLock.Unlock()
	defer func() {
		mach.secretLock.Lock()
		delete(mach.secretListeners, requestID)
		mach.secretLock.Unlock()
	}()

	// request secret from any device
	err = mach.sendToOneDevice(ctx, mach.Client.UserID, id.DeviceID("*"), event.ToDeviceSecretRequest, &event.SecretRequestEventContent{
		Action:             event.SecretRequestRequest,
		RequestID:          requestID,
		Name:               name,
		RequestingDeviceID: mach.Client.DeviceID,
	})
	if err != nil {
		return
	}

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-time.After(timeout):
	case secret = <-secretChan:
	}

	if secret != "" {
		err = mach.CryptoStore.PutSecret(ctx, name, secret)
	}
	return
}

func (mach *OlmMachine) HandleSecretRequest(ctx context.Context, userID id.UserID, content *event.SecretRequestEventContent) {
	log := mach.machOrContextLog(ctx).With().
		Stringer("user_id", userID).
		Stringer("requesting_device_id", content.RequestingDeviceID).
		Stringer("action", content.Action).
		Str("request_id", content.RequestID).
		Stringer("secret", content.Name).
		Logger()

	log.Trace().Msg("Handling secret request")

	if content.Action == event.SecretRequestCancellation {
		log.Trace().Msg("Secret request cancellation is unimplemented, ignoring")
		return
	} else if content.Action != event.SecretRequestRequest {
		log.Warn().Msg("Ignoring unknown secret request action")
		return
	}

	// immediately ignore requests from other users
	if userID != mach.Client.UserID || content.RequestingDeviceID == "" {
		log.Debug().Msg("Secret request was not from our own device, ignoring")
		return
	}

	if content.RequestingDeviceID == mach.Client.DeviceID {
		log.Debug().Msg("Secret request was from this device, ignoring")
		return
	}

	keys, err := mach.CryptoStore.GetCrossSigningKeys(ctx, mach.Client.UserID)
	if err != nil {
		log.Err(err).Msg("Failed to get cross signing keys from crypto store")
		return
	}

	crossSigningKey, ok := keys[id.XSUsageSelfSigning]
	if !ok {
		log.Warn().Msg("Couldn't find self signing key to verify requesting device")
		return
	}

	device, err := mach.GetOrFetchDevice(ctx, mach.Client.UserID, content.RequestingDeviceID)
	if err != nil {
		log.Err(err).Msg("Failed to get or fetch requesting device")
		return
	}

	verified, err := mach.CryptoStore.IsKeySignedBy(ctx, mach.Client.UserID, device.SigningKey, mach.Client.UserID, crossSigningKey.Key)
	if err != nil {
		log.Err(err).Msg("Failed to check if requesting device is verified")
		return
	}

	if !verified {
		log.Warn().Msg("Requesting device is not verified, ignoring request")
		return
	}

	secret, err := mach.CryptoStore.GetSecret(ctx, content.Name)
	if err != nil {
		log.Err(err).Msg("Failed to get secret from store")
		return
	} else if secret != "" {
		log.Debug().Msg("Responding to secret request")
		mach.sendToOneDevice(ctx, mach.Client.UserID, content.RequestingDeviceID, event.ToDeviceSecretRequest, &event.SecretSendEventContent{
			RequestID: content.RequestID,
			Secret:    secret,
		})
	} else {
		log.Debug().Msg("No stored secret found, secret request ignored")
	}
}

func (mach *OlmMachine) receiveSecret(ctx context.Context, evt *DecryptedOlmEvent, content *event.SecretSendEventContent) {
	log := mach.machOrContextLog(ctx).With().
		Stringer("sender", evt.Sender).
		Stringer("sender_device", evt.SenderDevice).
		Str("request_id", content.RequestID).
		Logger()

	log.Trace().Msg("Handling secret send request")

	// immediately ignore secrets from other users
	if evt.Sender != mach.Client.UserID {
		log.Warn().Msg("Secret send was not from our own device")
		return
	} else if content.Secret == "" {
		log.Warn().Msg("We were sent an empty secret")
		return
	}

	mach.secretLock.Lock()
	secretChan := mach.secretListeners[content.RequestID]
	mach.secretLock.Unlock()

	if secretChan == nil {
		log.Warn().Msg("We were sent a secret we didn't request")
		return
	}

	select {
	case secretChan <- content.Secret:
	default:
	}

	// best effort cancel this for all other targets
	go func() {
		mach.sendToOneDevice(ctx, mach.Client.UserID, id.DeviceID("*"), event.ToDeviceSecretRequest, &event.SecretRequestEventContent{
			Action:             event.SecretRequestCancellation,
			RequestID:          content.RequestID,
			RequestingDeviceID: mach.Client.DeviceID,
		})
	}()
}
