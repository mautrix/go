// Copyright (c) 2020 Nikos Filippakis
// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/crypto/signatures"
	"github.com/element-hq/mautrix-go/id"
)

func (mach *OlmMachine) storeCrossSigningKeys(ctx context.Context, crossSigningKeys map[id.UserID]mautrix.CrossSigningKeys, deviceKeys map[id.UserID]map[id.DeviceID]mautrix.DeviceKeys) {
	log := mach.machOrContextLog(ctx)
	for userID, userKeys := range crossSigningKeys {
		log := log.With().Str("user_id", userID.String()).Logger()
		currentKeys, err := mach.CryptoStore.GetCrossSigningKeys(ctx, userID)
		if err != nil {
			log.Error().Err(err).
				Msg("Error fetching current cross-signing keys of user")
		}
		if currentKeys != nil {
			for curKeyUsage, curKey := range currentKeys {
				log := log.With().Str("old_key", curKey.Key.String()).Str("old_key_usage", string(curKeyUsage)).Logger()
				// got a new key with the same usage as an existing key
				for _, newKeyUsage := range userKeys.Usage {
					if newKeyUsage == curKeyUsage {
						if _, ok := userKeys.Keys[id.NewKeyID(id.KeyAlgorithmEd25519, curKey.Key.String())]; !ok {
							// old key is not in the new key map, so we drop signatures made by it
							if count, err := mach.CryptoStore.DropSignaturesByKey(ctx, userID, curKey.Key); err != nil {
								log.Error().Err(err).Msg("Error deleting old signatures made by user")
							} else {
								log.Debug().
									Int64("signature_count", count).
									Msg("Dropped signatures made by old key as it has been replaced")
							}
						}
						break
					}
				}
			}
		}

		for _, key := range userKeys.Keys {
			log := log.With().Str("key", key.String()).Strs("usages", strishArray(userKeys.Usage)).Logger()
			for _, usage := range userKeys.Usage {
				log.Debug().Str("usage", string(usage)).Msg("Storing cross-signing key")
				if err = mach.CryptoStore.PutCrossSigningKey(ctx, userID, usage, key); err != nil {
					log.Error().Err(err).Msg("Error storing cross-signing key")
				}
			}

			for signUserID, keySigs := range userKeys.Signatures {
				for signKeyID, signature := range keySigs {
					_, signKeyName := signKeyID.Parse()
					signingKey := id.Ed25519(signKeyName)
					log := log.With().
						Str("sign_key_id", signKeyID.String()).
						Str("signer_user_id", signUserID.String()).
						Str("signing_key", signingKey.String()).
						Logger()
					// if the signer is one of this user's own devices, find the key from the key ID
					if signUserID == userID {
						ownDeviceID := id.DeviceID(signKeyName)
						if ownDeviceKeys, ok := deviceKeys[userID][ownDeviceID]; ok {
							signingKey = ownDeviceKeys.Keys.GetEd25519(ownDeviceID)
							log.Trace().
								Str("device_id", signKeyName).
								Msg("Treating key name as device ID")
						}
					}
					if len(signingKey) != 43 {
						log.Debug().Msg("Cross-signing key has a signature from an unknown key")
						continue
					}

					log.Debug().Msg("Verifying cross-signing key signature")
					if verified, err := signatures.VerifySignatureJSON(userKeys, signUserID, signKeyName, signingKey); err != nil {
						log.Warn().Err(err).Msg("Error verifying cross-signing key signature")
					} else {
						if verified {
							log.Debug().Err(err).Msg("Cross-signing key signature verified")
							err = mach.CryptoStore.PutSignature(ctx, userID, key, signUserID, signingKey, signature)
							if err != nil {
								log.Error().Err(err).Msg("Error storing cross-signing key signature")
							}
						} else {
							log.Warn().Err(err).Msg("Cross-siging key signature is invalid")
						}
					}
				}
			}
		}
	}
}
