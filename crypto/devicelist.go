// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"errors"
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

var (
	MismatchingDeviceID   = errors.New("mismatching device ID in parameter and keys object")
	MismatchingUserID     = errors.New("mismatching user ID in parameter and keys object")
	MismatchingSigningKey = errors.New("received update for device with different signing key")
	NoSigningKeyFound     = errors.New("didn't find ed25519 signing key")
	NoIdentityKeyFound    = errors.New("didn't find curve25519 identity key")
	InvalidKeySignature   = errors.New("invalid signature on device keys")
)

func (mach *OlmMachine) LoadDevices(user id.UserID) map[id.DeviceID]*DeviceIdentity {
	return mach.fetchKeys([]id.UserID{user}, "", true)[user]
}

func (mach *OlmMachine) fetchKeys(users []id.UserID, sinceToken string, includeUntracked bool) (data map[id.UserID]map[id.DeviceID]*DeviceIdentity) {
	req := &mautrix.ReqQueryKeys{
		DeviceKeys: mautrix.DeviceKeysRequest{},
		Timeout:    10 * 1000,
		Token:      sinceToken,
	}
	if !includeUntracked {
		users = mach.CryptoStore.FilterTrackedUsers(users)
	}
	if len(users) == 0 {
		return
	}
	for _, userID := range users {
		req.DeviceKeys[userID] = mautrix.DeviceIDList{}
	}
	mach.Log.Trace("Querying keys for %v", users)
	resp, err := mach.Client.QueryKeys(req)
	if err != nil {
		mach.Log.Warn("Failed to query keys: %v", err)
		return
	}
	for server, err := range resp.Failures {
		mach.Log.Warn("Query keys failure for %s: %v", server, err)
	}
	mach.Log.Trace("Query key result received with %d users", len(resp.DeviceKeys))
	data = make(map[id.UserID]map[id.DeviceID]*DeviceIdentity)
	for userID, devices := range resp.DeviceKeys {
		delete(req.DeviceKeys, userID)

		newDevices := make(map[id.DeviceID]*DeviceIdentity)
		existingDevices, err := mach.CryptoStore.GetDevices(userID)
		if err != nil {
			mach.Log.Warn("Failed to get existing devices for %s: %v", userID, err)
			existingDevices = make(map[id.DeviceID]*DeviceIdentity)
		}
		mach.Log.Trace("Updating devices for %s, got %d devices, have %d in store", userID, len(devices), len(existingDevices))
		changed := false
		for deviceID, deviceKeys := range devices {
			existing, ok := existingDevices[deviceID]
			if !ok {
				// New device
				changed = true
			}
			mach.Log.Trace("Validating device %s of %s", deviceID, userID)
			newDevice, err := mach.validateDevice(userID, deviceID, deviceKeys, existing)
			if err != nil {
				mach.Log.Error("Failed to validate device %s of %s: %v", deviceID, userID, err)
			} else if newDevice != nil {
				newDevices[deviceID] = newDevice
				for signerUserID, signerKeys := range deviceKeys.Signatures {
					for signerKey, signature := range signerKeys {
						// verify and save self-signing key signature for each device
						if selfSignKeys, ok := resp.SelfSigningKeys[signerUserID]; ok {
							for _, pubKey := range selfSignKeys.Keys {
								if selfSigs, ok := deviceKeys.Signatures[signerUserID]; !ok {
									continue
								} else if _, ok := selfSigs[id.NewKeyID(id.KeyAlgorithmEd25519, pubKey.String())]; !ok {
									continue
								}
								if verified, err := olm.VerifySignatureJSON(deviceKeys, signerUserID, pubKey.String(), pubKey); verified {
									if signKey, ok := deviceKeys.Keys[id.DeviceKeyID(signerKey)]; ok {
										signature := deviceKeys.Signatures[signerUserID][id.NewKeyID(id.KeyAlgorithmEd25519, pubKey.String())]
										mach.Log.Trace("Verified self-signing signature for device %v: `%v`", deviceID, signature)
										mach.CryptoStore.PutSignature(userID, id.Ed25519(signKey), signerUserID, pubKey, signature)
									}
								} else {
									mach.Log.Warn("Could not verify device self-signing signatures: %v", err)
								}
							}
						}
						// save signature of device made by its own device signing key
						if signKey, ok := deviceKeys.Keys[id.DeviceKeyID(signerKey)]; ok {
							mach.CryptoStore.PutSignature(userID, id.Ed25519(signKey), signerUserID, id.Ed25519(signKey), signature)
						}
					}
				}
			}
		}
		mach.Log.Trace("Storing new device list for %s containing %d devices", userID, len(newDevices))
		err = mach.CryptoStore.PutDevices(userID, newDevices)
		if err != nil {
			mach.Log.Warn("Failed to update device list for %s: %v", userID, err)
		}
		data[userID] = newDevices

		changed = changed || len(newDevices) != len(existingDevices)
		if changed {
			mach.OnDevicesChanged(userID)
		}
	}
	for userID := range req.DeviceKeys {
		mach.Log.Warn("Didn't get any keys for user %s", userID)
	}

	mach.storeCrossSigningKeys(resp.MasterKeys, resp.DeviceKeys)
	mach.storeCrossSigningKeys(resp.SelfSigningKeys, resp.DeviceKeys)
	mach.storeCrossSigningKeys(resp.UserSigningKeys, resp.DeviceKeys)

	return data
}

// OnDevicesChanged finds all shared rooms with the given user and invalidates outbound sessions in those rooms.
//
// This is called automatically whenever a device list change is noticed in ProcessSyncResponse and usually does
// not need to be called manually.
func (mach *OlmMachine) OnDevicesChanged(userID id.UserID) {
	for _, roomID := range mach.StateStore.FindSharedRooms(userID) {
		mach.Log.Debug("Devices of %s changed, invalidating group session for %s", userID, roomID)
		err := mach.CryptoStore.RemoveOutboundGroupSession(roomID)
		if err != nil {
			mach.Log.Warn("Failed to invalidate outbound group session of %s on device change for %s: %v", roomID, userID, err)
		}
	}
}

func (mach *OlmMachine) validateDevice(userID id.UserID, deviceID id.DeviceID, deviceKeys mautrix.DeviceKeys, existing *DeviceIdentity) (*DeviceIdentity, error) {
	if deviceID != deviceKeys.DeviceID {
		return nil, MismatchingDeviceID
	} else if userID != deviceKeys.UserID {
		return nil, MismatchingUserID
	}

	signingKey := deviceKeys.Keys.GetEd25519(deviceID)
	identityKey := deviceKeys.Keys.GetCurve25519(deviceID)
	if signingKey == "" {
		return nil, NoSigningKeyFound
	} else if identityKey == "" {
		return nil, NoIdentityKeyFound
	}

	if existing != nil && existing.SigningKey != signingKey {
		return existing, MismatchingSigningKey
	}

	ok, err := olm.VerifySignatureJSON(deviceKeys, userID, deviceID.String(), signingKey)
	if err != nil {
		return existing, fmt.Errorf("failed to verify signature: %w", err)
	} else if !ok {
		return existing, InvalidKeySignature
	}

	name, ok := deviceKeys.Unsigned["device_display_name"].(string)
	if !ok {
		name = string(deviceID)
	}

	return &DeviceIdentity{
		UserID:      userID,
		DeviceID:    deviceID,
		IdentityKey: identityKey,
		SigningKey:  signingKey,
		Trust:       TrustStateUnset,
		Name:        name,
		Deleted:     false,
	}, nil
}
