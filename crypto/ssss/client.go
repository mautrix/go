// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ssss

import (
	"context"
	"fmt"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/event"
)

// Machine contains utility methods for interacting with SSSS data on the server.
type Machine struct {
	Client *mautrix.Client
}

func NewSSSSMachine(client *mautrix.Client) *Machine {
	return &Machine{
		Client: client,
	}
}

type DefaultSecretStorageKeyContent struct {
	KeyID string `json:"key"`
}

// GetDefaultKeyID retrieves the default key ID for this account from SSSS.
func (mach *Machine) GetDefaultKeyID(ctx context.Context) (string, error) {
	var data DefaultSecretStorageKeyContent
	err := mach.Client.GetAccountData(ctx, event.AccountDataSecretStorageDefaultKey.Type, &data)
	if err != nil {
		if httpErr, ok := err.(mautrix.HTTPError); ok && httpErr.RespError != nil && httpErr.RespError.ErrCode == "M_NOT_FOUND" {
			return "", ErrNoDefaultKeyAccountDataEvent
		}
		return "", fmt.Errorf("failed to get default key account data from server: %w", err)
	}
	if len(data.KeyID) == 0 {
		return "", ErrNoKeyFieldInAccountDataEvent
	}
	return data.KeyID, nil
}

// SetDefaultKeyID sets the default key ID for this account on the server.
func (mach *Machine) SetDefaultKeyID(ctx context.Context, keyID string) error {
	return mach.Client.SetAccountData(ctx, event.AccountDataSecretStorageDefaultKey.Type, &DefaultSecretStorageKeyContent{keyID})
}

// GetKeyData gets the details about the given key ID.
func (mach *Machine) GetKeyData(ctx context.Context, keyID string) (keyData *KeyMetadata, err error) {
	keyData = &KeyMetadata{id: keyID}
	err = mach.Client.GetAccountData(ctx, fmt.Sprintf("%s.%s", event.AccountDataSecretStorageKey.Type, keyID), keyData)
	return
}

// SetKeyData stores SSSS key metadata on the server.
func (mach *Machine) SetKeyData(ctx context.Context, keyID string, keyData *KeyMetadata) error {
	return mach.Client.SetAccountData(ctx, fmt.Sprintf("%s.%s", event.AccountDataSecretStorageKey.Type, keyID), keyData)
}

// GetDefaultKeyData gets the details about the default key ID (see GetDefaultKeyID).
func (mach *Machine) GetDefaultKeyData(ctx context.Context) (keyID string, keyData *KeyMetadata, err error) {
	keyID, err = mach.GetDefaultKeyID(ctx)
	if err != nil {
		return
	}
	keyData, err = mach.GetKeyData(ctx, keyID)
	return
}

// GetDecryptedAccountData gets the account data event with the given event type and decrypts it using the given key.
func (mach *Machine) GetDecryptedAccountData(ctx context.Context, eventType event.Type, key *Key) ([]byte, error) {
	var encData EncryptedAccountDataEventContent
	err := mach.Client.GetAccountData(ctx, eventType.Type, &encData)
	if err != nil {
		return nil, err
	}
	return encData.Decrypt(eventType.Type, key)
}

// SetEncryptedAccountData encrypts the given data with the given keys and stores it on the server.
func (mach *Machine) SetEncryptedAccountData(ctx context.Context, eventType event.Type, data []byte, keys ...*Key) error {
	if len(keys) == 0 {
		return ErrNoKeyGiven
	}
	encrypted := make(map[string]EncryptedKeyData, len(keys))
	for _, key := range keys {
		encrypted[key.ID] = key.Encrypt(eventType.Type, data)
	}
	return mach.Client.SetAccountData(ctx, eventType.Type, &EncryptedAccountDataEventContent{Encrypted: encrypted})
}

// GenerateAndUploadKey generates a new SSSS key and stores the metadata on the server.
func (mach *Machine) GenerateAndUploadKey(ctx context.Context, passphrase string) (key *Key, err error) {
	key, err = NewKey(passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	err = mach.SetKeyData(ctx, key.ID, key.Metadata)
	if err != nil {
		err = fmt.Errorf("failed to upload key: %w", err)
	}
	return key, err
}
