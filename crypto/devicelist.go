// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exzerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"
)

var (
	MismatchingDeviceID   = errors.New("mismatching device ID in parameter and keys object")
	MismatchingUserID     = errors.New("mismatching user ID in parameter and keys object")
	MismatchingSigningKey = errors.New("received update for device with different signing key")
	NoSigningKeyFound     = errors.New("didn't find ed25519 signing key")
	NoIdentityKeyFound    = errors.New("didn't find curve25519 identity key")
	InvalidKeySignature   = errors.New("invalid signature on device keys")

	ErrUserNotTracked = errors.New("user is not tracked")
)

func (mach *OlmMachine) LoadDevices(ctx context.Context, user id.UserID) (keys map[id.DeviceID]*id.Device) {
	log := zerolog.Ctx(ctx)

	if keys, err := mach.FetchKeys(ctx, []id.UserID{user}, true); err != nil {
		log.Err(err).Msg("Failed to load devices")
	} else if keys != nil {
		return keys[user]
	}

	return nil
}

type CachedDevices struct {
	Devices                []*id.Device
	MasterKey              *id.CrossSigningKey
	HasValidSelfSigningKey bool
	MasterKeySignedByUs    bool
}

func (mach *OlmMachine) GetCachedDevices(ctx context.Context, userID id.UserID) (*CachedDevices, error) {
	userIDs, err := mach.CryptoStore.FilterTrackedUsers(ctx, []id.UserID{userID})
	if err != nil {
		return nil, fmt.Errorf("failed to check if user's devices are tracked: %w", err)
	} else if len(userIDs) == 0 {
		return nil, ErrUserNotTracked
	}
	ownKeys := mach.GetOwnCrossSigningPublicKeys(ctx)
	var ownUserSigningKey id.Ed25519
	if ownKeys != nil {
		ownUserSigningKey = ownKeys.UserSigningKey
	}
	var resp CachedDevices
	csKeys, err := mach.CryptoStore.GetCrossSigningKeys(ctx, userID)
	theirMasterKey := csKeys[id.XSUsageMaster]
	theirSelfSignKey := csKeys[id.XSUsageSelfSigning]
	if err != nil {
		return nil, fmt.Errorf("failed to get cross-signing keys: %w", err)
	} else if csKeys != nil && theirMasterKey.Key != "" {
		resp.MasterKey = &theirMasterKey
		if theirSelfSignKey.Key != "" {
			resp.HasValidSelfSigningKey, err = mach.CryptoStore.IsKeySignedBy(ctx, userID, theirSelfSignKey.Key, userID, theirMasterKey.Key)
			if err != nil {
				return nil, fmt.Errorf("failed to check if self-signing key is signed by master key: %w", err)
			}
		}
	}
	devices, err := mach.CryptoStore.GetDevices(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}
	if userID == mach.Client.UserID {
		if ownKeys != nil && ownKeys.MasterKey == theirMasterKey.Key {
			resp.MasterKeySignedByUs, err = mach.CryptoStore.IsKeySignedBy(ctx, userID, theirMasterKey.Key, userID, mach.OwnIdentity().SigningKey)
		}
	} else if ownUserSigningKey != "" && theirMasterKey.Key != "" {
		// TODO should own master key and user-signing key signatures be checked here too?
		resp.MasterKeySignedByUs, err = mach.CryptoStore.IsKeySignedBy(ctx, userID, theirMasterKey.Key, mach.Client.UserID, ownUserSigningKey)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to check if user is trusted: %w", err)
	}
	resp.Devices = make([]*id.Device, len(devices))
	i := 0
	for _, device := range devices {
		resp.Devices[i] = device
		if resp.HasValidSelfSigningKey && device.Trust == id.TrustStateUnset {
			signed, err := mach.CryptoStore.IsKeySignedBy(ctx, device.UserID, device.SigningKey, device.UserID, theirSelfSignKey.Key)
			if err != nil {
				return nil, fmt.Errorf("failed to check if device %s is signed by self-signing key: %w", device.DeviceID, err)
			} else if signed {
				if resp.MasterKeySignedByUs {
					device.Trust = id.TrustStateCrossSignedVerified
				} else if theirMasterKey.Key == theirMasterKey.First {
					device.Trust = id.TrustStateCrossSignedTOFU
				} else {
					device.Trust = id.TrustStateCrossSignedUntrusted
				}
			}
		}
		i++
	}
	slices.SortFunc(resp.Devices, func(a, b *id.Device) int {
		return strings.Compare(a.DeviceID.String(), b.DeviceID.String())
	})
	return &resp, nil
}

func (mach *OlmMachine) storeDeviceSelfSignatures(ctx context.Context, userID id.UserID, deviceID id.DeviceID, resp *mautrix.RespQueryKeys) {
	log := zerolog.Ctx(ctx)
	deviceKeys := resp.DeviceKeys[userID][deviceID]
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
					if verified, err := signatures.VerifySignatureJSON(deviceKeys, signerUserID, pubKey.String(), pubKey); verified {
						if signKey, ok := deviceKeys.Keys[id.DeviceKeyID(signerKey)]; ok {
							signature := deviceKeys.Signatures[signerUserID][id.NewKeyID(id.KeyAlgorithmEd25519, pubKey.String())]
							log.Trace().Err(err).
								Str("signer_user_id", signerUserID.String()).
								Str("signed_device_id", deviceID.String()).
								Str("signature", signature).
								Msg("Verified self-signing signature")
							err = mach.CryptoStore.PutSignature(ctx, userID, id.Ed25519(signKey), signerUserID, pubKey, signature)
							if err != nil {
								log.Warn().Err(err).
									Str("signer_user_id", signerUserID.String()).
									Str("signed_device_id", deviceID.String()).
									Msg("Failed to store self-signing signature")
							}
						}
					} else {
						if err == nil {
							err = errors.New("invalid signature")
						}
						log.Warn().Err(err).
							Str("signer_user_id", signerUserID.String()).
							Str("signed_device_id", deviceID.String()).
							Msg("Failed to verify self-signing signature")
					}
				}
			}
			// save signature of device made by its own device signing key
			if signKey, ok := deviceKeys.Keys[id.DeviceKeyID(signerKey)]; ok {
				err := mach.CryptoStore.PutSignature(ctx, userID, id.Ed25519(signKey), signerUserID, id.Ed25519(signKey), signature)
				if err != nil {
					log.Warn().Err(err).
						Str("signer_user_id", signerUserID.String()).
						Str("signer_key", signKey).
						Msg("Failed to store self-signing signature")
				}
			}
		}
	}
}

// FetchKeys fetches the devices of a list of other users. If includeUntracked
// is set to false, then the users are filtered to to only include user IDs
// whose device lists have been stored with the PutDevices function on the
// [Store]. See the FilterTrackedUsers function on [Store] for details.
func (mach *OlmMachine) FetchKeys(ctx context.Context, users []id.UserID, includeUntracked bool) (data map[id.UserID]map[id.DeviceID]*id.Device, err error) {
	req := &mautrix.ReqQueryKeys{
		DeviceKeys: mautrix.DeviceKeysRequest{},
		Timeout:    10 * 1000,
	}
	log := mach.machOrContextLog(ctx)
	if !includeUntracked {
		users, err = mach.CryptoStore.FilterTrackedUsers(ctx, users)
		if err != nil {
			return nil, fmt.Errorf("failed to filter tracked user list: %w", err)
		}
	}
	if len(users) == 0 {
		return
	}
	for _, userID := range users {
		req.DeviceKeys[userID] = mautrix.DeviceIDList{}
	}
	log.Debug().Array("users", exzerolog.ArrayOfStrs(users)).Msg("Querying keys for users")
	resp, err := mach.Client.QueryKeys(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}
	for server, err := range resp.Failures {
		log.Warn().Interface("query_error", err).Str("server", server).Msg("Query keys failure for server")
	}
	log.Trace().Int("user_count", len(resp.DeviceKeys)).Msg("Query key result received")
	data = make(map[id.UserID]map[id.DeviceID]*id.Device)
	for userID, devices := range resp.DeviceKeys {
		log := log.With().Str("user_id", userID.String()).Logger()
		delete(req.DeviceKeys, userID)

		newDevices := make(map[id.DeviceID]*id.Device)
		existingDevices, err := mach.CryptoStore.GetDevices(ctx, userID)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to get existing devices for user")
			existingDevices = make(map[id.DeviceID]*id.Device)
		}

		log.Debug().
			Int("new_device_count", len(devices)).
			Int("old_device_count", len(existingDevices)).
			Msg("Updating devices in store")
		changed := false
		for deviceID, deviceKeys := range devices {
			log := log.With().Str("device_id", deviceID.String()).Logger()
			existing, ok := existingDevices[deviceID]
			if !ok {
				// New device
				changed = true
			}
			log.Trace().Msg("Validating device")
			newDevice, err := mach.validateDevice(userID, deviceID, deviceKeys, existing)
			if err != nil {
				log.Error().Err(err).Msg("Failed to validate device")
			} else if newDevice != nil {
				newDevices[deviceID] = newDevice
				mach.storeDeviceSelfSignatures(ctx, userID, deviceID, resp)
			}
		}
		log.Trace().Int("new_device_count", len(newDevices)).Msg("Storing new device list")
		err = mach.CryptoStore.PutDevices(ctx, userID, newDevices)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to update device list")
		}
		data[userID] = newDevices

		changed = changed || len(newDevices) != len(existingDevices)
		if changed {
			if mach.DeleteKeysOnDeviceDelete {
				for deviceID := range newDevices {
					delete(existingDevices, deviceID)
				}
				for _, device := range existingDevices {
					log := log.With().
						Str("device_id", device.DeviceID.String()).
						Str("identity_key", device.IdentityKey.String()).
						Str("signing_key", device.SigningKey.String()).
						Logger()
					sessionIDs, err := mach.CryptoStore.RedactGroupSessions(ctx, "", device.IdentityKey, "device removed")
					if err != nil {
						log.Err(err).Msg("Failed to redact megolm sessions from deleted device")
					} else {
						log.Info().
							Array("session_ids", exzerolog.ArrayOfStrs(sessionIDs)).
							Msg("Redacted megolm sessions from deleted device")
					}
				}
			}
			mach.OnDevicesChanged(ctx, userID)
		}
	}
	for userID := range req.DeviceKeys {
		log.Warn().Str("user_id", userID.String()).Msg("Didn't get any keys for user")
	}

	mach.storeCrossSigningKeys(ctx, resp.MasterKeys, resp.DeviceKeys)
	mach.storeCrossSigningKeys(ctx, resp.SelfSigningKeys, resp.DeviceKeys)
	mach.storeCrossSigningKeys(ctx, resp.UserSigningKeys, resp.DeviceKeys)

	return data, nil
}

// OnDevicesChanged finds all shared rooms with the given user and invalidates outbound sessions in those rooms.
//
// This is called automatically whenever a device list change is noticed in ProcessSyncResponse and usually does
// not need to be called manually.
func (mach *OlmMachine) OnDevicesChanged(ctx context.Context, userID id.UserID) {
	if mach.DisableDeviceChangeKeyRotation {
		return
	}
	rooms, err := mach.StateStore.FindSharedRooms(ctx, userID)
	if err != nil {
		mach.machOrContextLog(ctx).Err(err).
			Stringer("with_user_id", userID).
			Msg("Failed to find shared rooms to invalidate group sessions")
		return
	}
	for _, roomID := range rooms {
		mach.machOrContextLog(ctx).Debug().
			Str("user_id", userID.String()).
			Str("room_id", roomID.String()).
			Msg("Invalidating group session in room due to device change notification")
		err = mach.CryptoStore.RemoveOutboundGroupSession(ctx, roomID)
		if err != nil {
			mach.machOrContextLog(ctx).Err(err).
				Str("user_id", userID.String()).
				Str("room_id", roomID.String()).
				Msg("Failed to invalidate outbound group session")
		}
	}
}

func (mach *OlmMachine) validateDevice(userID id.UserID, deviceID id.DeviceID, deviceKeys mautrix.DeviceKeys, existing *id.Device) (*id.Device, error) {
	if deviceID != deviceKeys.DeviceID {
		return nil, fmt.Errorf("%w (expected %s, got %s)", MismatchingDeviceID, deviceID, deviceKeys.DeviceID)
	} else if userID != deviceKeys.UserID {
		return nil, fmt.Errorf("%w (expected %s, got %s)", MismatchingUserID, userID, deviceKeys.UserID)
	}

	signingKey := deviceKeys.Keys.GetEd25519(deviceID)
	identityKey := deviceKeys.Keys.GetCurve25519(deviceID)
	if signingKey == "" {
		return nil, NoSigningKeyFound
	} else if identityKey == "" {
		return nil, NoIdentityKeyFound
	}

	if existing != nil && existing.SigningKey != signingKey {
		return existing, fmt.Errorf("%w (expected %s, got %s)", MismatchingSigningKey, existing.SigningKey, signingKey)
	}

	ok, err := signatures.VerifySignatureJSON(deviceKeys, userID, deviceID.String(), signingKey)
	if err != nil {
		return existing, fmt.Errorf("failed to verify signature: %w", err)
	} else if !ok {
		return existing, InvalidKeySignature
	}

	name, ok := deviceKeys.Unsigned["device_display_name"].(string)
	if !ok {
		name = string(deviceID)
	}

	return &id.Device{
		UserID:      userID,
		DeviceID:    deviceID,
		IdentityKey: identityKey,
		SigningKey:  signingKey,
		Trust:       id.TrustStateUnset,
		Name:        name,
		Deleted:     false,
	}, nil
}
