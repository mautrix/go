// Copyright (c) 2020 Nikos Filippakis
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
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	ErrCrossSigningKeysNotCached = errors.New("cross-signing private keys not in cache")
	ErrUserSigningKeyNotCached   = errors.New("user-signing private key not in cache")
	ErrSelfSigningKeyNotCached   = errors.New("self-signing private key not in cache")
	ErrSignatureUploadFail       = errors.New("server-side failure uploading signatures")
	ErrCantSignOwnMasterKey      = errors.New("signing your own master key is not allowed")
	ErrCantSignOtherDevice       = errors.New("signing other users' devices is not allowed")
	ErrUserNotInQueryResponse    = errors.New("could not find user in query keys response")
	ErrDeviceNotInQueryResponse  = errors.New("could not find device in query keys response")
	ErrOlmAccountNotLoaded       = errors.New("olm account has not been loaded")

	ErrCrossSigningMasterKeyNotFound = errors.New("cross-signing master key not found")
	ErrMasterKeyMACNotFound          = errors.New("found cross-signing master key, but didn't find corresponding MAC in verification request")
	ErrMismatchingMasterKeyMAC       = errors.New("mismatching cross-signing master key MAC")
)

func (mach *OlmMachine) fetchMasterKey(device *DeviceIdentity, content *event.VerificationMacEventContent, verState *verificationState, transactionID string) (id.Ed25519, error) {
	crossSignKeys, err := mach.CryptoStore.GetCrossSigningKeys(device.UserID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch cross-signing keys: %w", err)
	}
	masterKey, ok := crossSignKeys[id.XSUsageMaster]
	if !ok {
		return "", ErrCrossSigningMasterKeyNotFound
	}
	masterKeyID := id.NewKeyID(id.KeyAlgorithmEd25519, masterKey.String())
	masterKeyMAC, ok := content.Mac[masterKeyID]
	if !ok {
		return masterKey, ErrMasterKeyMACNotFound
	}
	expectedMasterKeyMAC, _, err := mach.getPKAndKeysMAC(verState.sas, device.UserID, device.DeviceID,
		mach.Client.UserID, mach.Client.DeviceID, transactionID, masterKey, masterKeyID, content.Mac)
	if err != nil {
		return masterKey, fmt.Errorf("failed to calculate expected MAC for master key: %w", err)
	}
	if masterKeyMAC != expectedMasterKeyMAC {
		err = fmt.Errorf("%w: expected %s, got %s", ErrMismatchingMasterKeyMAC, expectedMasterKeyMAC, masterKeyMAC)
	}
	return masterKey, err
}

// SignUser creates a cross-signing signature for a user, stores it and uploads it to the server.
func (mach *OlmMachine) SignUser(userID id.UserID, masterKey id.Ed25519) error {
	if userID == mach.Client.UserID {
		return ErrCantSignOwnMasterKey
	} else if mach.CrossSigningKeys == nil || mach.CrossSigningKeys.UserSigningKey == nil {
		return ErrUserSigningKeyNotCached
	}

	masterKeyObj := mautrix.ReqKeysSignatures{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
		Keys: map[id.KeyID]string{
			id.NewKeyID(id.KeyAlgorithmEd25519, masterKey.String()): masterKey.String(),
		},
	}

	signature, err := mach.signAndUpload(masterKeyObj, userID, masterKey.String(), mach.CrossSigningKeys.UserSigningKey)
	if err != nil {
		return err
	}

	mach.Log.Trace("Signed master key of %s with user-signing key: `%v`", userID, signature)

	if err := mach.CryptoStore.PutSignature(userID, masterKey, mach.Client.UserID, mach.CrossSigningKeys.UserSigningKey.PublicKey, signature); err != nil {
		return fmt.Errorf("error storing signature in crypto store: %w", err)
	}

	return nil
}

// SignOwnMasterKey uses the current account for signing the current user's master key and uploads the signature.
func (mach *OlmMachine) SignOwnMasterKey() error {
	if mach.CrossSigningKeys == nil {
		return ErrCrossSigningKeysNotCached
	} else if mach.account == nil {
		return ErrOlmAccountNotLoaded
	}

	userID := mach.Client.UserID
	deviceID := mach.Client.DeviceID
	masterKey := mach.CrossSigningKeys.MasterKey.PublicKey

	masterKeyObj := mautrix.ReqKeysSignatures{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
		Keys: map[id.KeyID]string{
			id.NewKeyID(id.KeyAlgorithmEd25519, masterKey.String()): masterKey.String(),
		},
	}
	signature, err := mach.account.Internal.SignJSON(masterKeyObj)
	if err != nil {
		return fmt.Errorf("failed to sign JSON: %w", err)
	}
	masterKeyObj.Signatures = mautrix.Signatures{
		userID: map[id.KeyID]string{
			id.NewKeyID(id.KeyAlgorithmEd25519, deviceID.String()): signature,
		},
	}
	mach.Log.Trace("Signed own master key with device %v: `%v`", deviceID, signature)

	resp, err := mach.Client.UploadSignatures(&mautrix.ReqUploadSignatures{
		userID: map[string]mautrix.ReqKeysSignatures{
			masterKey.String(): masterKeyObj,
		},
	})

	if err != nil {
		return fmt.Errorf("error while uploading signatures: %w", err)
	} else if len(resp.Failures) > 0 {
		return fmt.Errorf("%w: %+v", ErrSignatureUploadFail, resp.Failures)
	}

	if err := mach.CryptoStore.PutSignature(userID, masterKey, userID, mach.account.SigningKey(), signature); err != nil {
		return fmt.Errorf("error storing signature in crypto store: %w", err)
	}

	return nil
}

// SignOwnDevice creates a cross-signing signature for a device belonging to the current user and uploads it to the server.
func (mach *OlmMachine) SignOwnDevice(device *DeviceIdentity) error {
	if device.UserID != mach.Client.UserID {
		return ErrCantSignOtherDevice
	} else if mach.CrossSigningKeys == nil || mach.CrossSigningKeys.SelfSigningKey == nil {
		return ErrSelfSigningKeyNotCached
	}

	deviceKeys, err := mach.getFullDeviceKeys(device)
	if err != nil {
		return err
	}

	deviceKeyObj := mautrix.ReqKeysSignatures{
		UserID:     device.UserID,
		DeviceID:   device.DeviceID,
		Algorithms: deviceKeys.Algorithms,
		Keys:       make(map[id.KeyID]string),
	}
	for keyID, key := range deviceKeys.Keys {
		deviceKeyObj.Keys[id.KeyID(keyID)] = key
	}

	signature, err := mach.signAndUpload(deviceKeyObj, device.UserID, device.DeviceID.String(), mach.CrossSigningKeys.SelfSigningKey)
	if err != nil {
		return err
	}

	mach.Log.Trace("Signed own device %s with self-signing key: `%v`", device.UserID, device.DeviceID, signature)

	if err := mach.CryptoStore.PutSignature(device.UserID, device.SigningKey, mach.Client.UserID, mach.CrossSigningKeys.SelfSigningKey.PublicKey, signature); err != nil {
		return fmt.Errorf("error storing signature in crypto store: %w", err)
	}

	return nil
}

// getFullDeviceKeys gets the full device keys object for the given device.
// This is used because we don't cache some of the details like list of algorithms and unsupported key types.
func (mach *OlmMachine) getFullDeviceKeys(device *DeviceIdentity) (*mautrix.DeviceKeys, error) {
	devicesKeys, err := mach.Client.QueryKeys(&mautrix.ReqQueryKeys{
		DeviceKeys: mautrix.DeviceKeysRequest{
			device.UserID: mautrix.DeviceIDList{device.DeviceID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error querying device keys for %s: %w", device.DeviceID, err)
	}
	userKeys, ok := devicesKeys.DeviceKeys[device.UserID]
	if !ok {
		return nil, ErrUserNotInQueryResponse
	}
	deviceKeys, ok := userKeys[device.DeviceID]
	if !ok {
		return nil, ErrDeviceNotInQueryResponse
	}
	_, err = mach.validateDevice(device.UserID, device.DeviceID, deviceKeys, device)
	return &deviceKeys, err
}

// signAndUpload signs the given key signatures object and uploads it to the server.
func (mach *OlmMachine) signAndUpload(req mautrix.ReqKeysSignatures, userID id.UserID, signedThing string, key *olm.PkSigning) (string, error) {
	signature, err := key.SignJSON(req)
	if err != nil {
		return "", fmt.Errorf("failed to sign JSON: %w", err)
	}
	req.Signatures = mautrix.Signatures{
		mach.Client.UserID: map[id.KeyID]string{
			id.NewKeyID(id.KeyAlgorithmEd25519, key.PublicKey.String()): signature,
		},
	}

	resp, err := mach.Client.UploadSignatures(&mautrix.ReqUploadSignatures{
		userID: map[string]mautrix.ReqKeysSignatures{
			signedThing: req,
		},
	})
	if err != nil {
		return "", fmt.Errorf("error while uploading signatures: %w", err)
	} else if len(resp.Failures) > 0 {
		return "", fmt.Errorf("%w: %+v", ErrSignatureUploadFail, resp.Failures)
	}
	return signature, nil
}
