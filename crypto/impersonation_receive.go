// Copyright (c) 2026 gchahcg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"
)

// impersonatableDevices holds the MSC4350 impersonatable devices seen in /keys/query responses, by user.
//
// They have no keys of their own, so they can't be stored as [id.Device]. They are validated when a message is
// received, because the impersonator's own device may not be known yet when the response arrives. The cache is
// in memory only: it is filled again the next time the user's keys are fetched.
type impersonatableDevices struct {
	lock    sync.RWMutex
	devices map[id.UserID][]*mautrix.DeviceKeys
}

func (d *impersonatableDevices) replace(userID id.UserID, devices []*mautrix.DeviceKeys) {
	d.lock.Lock()
	defer d.lock.Unlock()
	if len(devices) == 0 {
		delete(d.devices, userID)
		return
	}
	if d.devices == nil {
		d.devices = make(map[id.UserID][]*mautrix.DeviceKeys)
	}
	d.devices[userID] = devices
}

func (d *impersonatableDevices) get(userID id.UserID) []*mautrix.DeviceKeys {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return d.devices[userID]
}

var (
	errNotImpersonatable           = errors.New("device keys don't contain an impersonator")
	errImpersonatableHasKeys       = errors.New("impersonatable device must not have algorithms or keys")
	errImpersonatorMismatch        = errors.New("impersonator doesn't match the device that sent the session")
	errImpersonatorKeysMismatch    = errors.New("impersonator keys don't match the impersonator device")
	errImpersonatableBadSignature  = errors.New("impersonatable device isn't signed by the impersonator")
	errImpersonatableNoSelfSigning = errors.New("user has cross-signing keys, but the impersonatable device isn't signed by their self-signing key")
)

// validateImpersonatableDevice checks that deviceKeys is a well-formed MSC4350 impersonatable device which
// impersonator (a device that has already been validated) signed.
//
// It checks that the algorithms and keys are empty, that the embedded impersonator is exactly the given device
// with its real keys (so the embedded object can't be used to smuggle in other keys), and that the impersonator
// signed the device keys object, including the embedded impersonator.
func validateImpersonatableDevice(deviceKeys *mautrix.DeviceKeys, impersonator *id.Device) error {
	embedded := deviceKeys.Impersonator
	if embedded == nil {
		return errNotImpersonatable
	} else if len(deviceKeys.Algorithms) != 0 || len(deviceKeys.Keys) != 0 {
		return errImpersonatableHasKeys
	} else if embedded.UserID != impersonator.UserID || embedded.DeviceID != impersonator.DeviceID {
		return errImpersonatorMismatch
	} else if embedded.Keys.GetEd25519(impersonator.DeviceID) != impersonator.SigningKey ||
		embedded.Keys.GetCurve25519(impersonator.DeviceID) != impersonator.IdentityKey {
		return errImpersonatorKeysMismatch
	}
	if valid, err := signatures.VerifySignatureJSON(deviceKeys, impersonator.UserID, impersonator.DeviceID.String(), impersonator.SigningKey); err != nil || !valid {
		return errImpersonatableBadSignature
	}
	return nil
}

// resolveImpersonation decides how to treat a message whose megolm session wasn't sent by a device of the
// message's sender, because the sender has an MSC4350 impersonatable device which allows the session's owner
// to send on their behalf.
//
// The message is trusted unless
//   - the impersonator isn't in the room,
//   - the impersonator's device isn't cross-signed, or
//   - the sender has cross-signing keys and hasn't signed the impersonatable device with their self-signing key.
//
// When trusted, the trust state of the impersonator's device is returned together with a device for the sender
// that carries the impersonator's keys. If no valid impersonatable device is found, ok is false and the caller
// should treat the message as it would without MSC4350.
func (mach *OlmMachine) resolveImpersonation(ctx context.Context, sender id.UserID, sess *InboundGroupSession) (trust id.TrustState, device *id.Device, ok bool) {
	log := mach.machOrContextLog(ctx)
	for _, candidate := range mach.impersonatable.get(sender) {
		if candidate.Impersonator == nil {
			continue
		}
		impersonatorUser := candidate.Impersonator.UserID
		impersonator, err := mach.CryptoStore.FindDeviceByKey(ctx, impersonatorUser, sess.SenderKey)
		if err == nil && impersonator == nil {
			impersonator, err = mach.GetOrFetchDeviceByKey(ctx, impersonatorUser, sess.SenderKey)
		}
		if err != nil || impersonator == nil || impersonator.SigningKey != sess.SigningKey {
			continue
		}
		if err = validateImpersonatableDevice(candidate, impersonator); err != nil {
			log.Debug().Err(err).Stringer("sender", sender).Stringer("device_id", candidate.DeviceID).
				Msg("Ignoring invalid impersonatable device")
			continue
		}
		if inRoom, err := mach.isInRoom(ctx, impersonatorUser, sess.RoomID); err != nil || !inRoom {
			log.Debug().Err(err).Stringer("sender", sender).Stringer("impersonator", impersonatorUser).
				Msg("Impersonator of the message sender isn't in the room")
			continue
		}
		trust, err = mach.ResolveTrustContext(ctx, impersonator)
		if err != nil || trust < id.TrustStateCrossSignedUntrusted {
			log.Debug().Err(err).Stringer("sender", sender).Stringer("impersonator", impersonatorUser).
				Msg("Impersonator's device isn't cross-signed")
			continue
		}
		if err = mach.checkSelfSigned(ctx, sender, candidate); err != nil {
			log.Debug().Err(err).Stringer("sender", sender).Msg("Ignoring impersonatable device")
			continue
		}
		return trust, &id.Device{
			UserID:      sender,
			DeviceID:    candidate.DeviceID,
			IdentityKey: impersonator.IdentityKey,
			SigningKey:  impersonator.SigningKey,
			Trust:       trust,
		}, true
	}
	return id.TrustStateUnset, nil, false
}

// isInRoom returns whether the user is in the room. The state store only exposes the encrypted rooms a user
// shares with us, and the message was received in such a room, so that is enough to answer the question.
func (mach *OlmMachine) isInRoom(ctx context.Context, userID id.UserID, roomID id.RoomID) (bool, error) {
	rooms, err := mach.StateStore.FindSharedRooms(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, room := range rooms {
		if room == roomID {
			return true, nil
		}
	}
	return false, nil
}

// checkSelfSigned makes sure that, if the sender has cross-signing keys, their self-signing key signed the
// impersonatable device. Senders without cross-signing keys, like most bridge ghosts, only need the
// impersonator's signature.
func (mach *OlmMachine) checkSelfSigned(ctx context.Context, sender id.UserID, deviceKeys *mautrix.DeviceKeys) error {
	keys, err := mach.CryptoStore.GetCrossSigningKeys(ctx, sender)
	if err != nil {
		return fmt.Errorf("failed to get cross-signing keys: %w", err)
	}
	ssk, ok := keys[id.XSUsageSelfSigning]
	if !ok {
		return nil
	}
	if valid, err := signatures.VerifySignatureJSON(deviceKeys, sender, ssk.Key.String(), ssk.Key); err != nil || !valid {
		return errImpersonatableNoSelfSigning
	}
	return nil
}
