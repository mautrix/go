// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"

	"github.com/pkg/errors"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

var (
	ErrMissingExportPrefix          = errors.New("invalid Matrix key export: missing prefix/suffix")
	ErrUnsupportedExportVersion     = errors.New("unsupported Matrix key export format version")
	ErrMismatchingExportHash        = errors.New("mismatching hash; incorrect passphrase?")
	ErrInvalidExportedAlgorithm     = errors.New("session has unknown algorithm")
	ErrMismatchingExportedSessionID = errors.New("imported session has different ID than expected")
)

func decryptKeyExport(passphrase string, exportData []byte) ([]ExportedSession, error) {
	if exportData[0] != 0x01 {
		return nil, ErrUnsupportedExportVersion
	}

	// Get all the different parts of the export
	salt := exportData[1:17]
	iv := exportData[17:33]
	passphraseRounds := binary.BigEndian.Uint32(exportData[33:37])
	dataWithoutHashLength := len(exportData) - exportHashLength
	encryptedData := exportData[exportHeaderLength:dataWithoutHashLength]
	hash := exportData[dataWithoutHashLength:]

	// Compute the encryption and hash keys from the passphrase and salt
	key := computeKey(passphrase, salt, int(passphraseRounds))
	encryptionKey := key[:256]
	hashKey := key[256:]

	// Compute and verify the hash. If it doesn't match, the passphrase is probably wrong
	mac := hmac.New(sha256.New, hashKey)
	mac.Write(exportData[:dataWithoutHashLength])
	if bytes.Compare(hash, mac.Sum(nil)) != 0 {
		return nil, ErrMismatchingExportHash
	}

	// Decrypt the export
	block, _ := aes.NewCipher(encryptionKey)
	unencryptedData := make([]byte, len(exportData)-exportHashLength-exportHeaderLength)
	cipher.NewCTR(block, iv).XORKeyStream(unencryptedData, encryptedData)

	// Parse the decrypted JSON
	var sessionsJSON []ExportedSession
	err := json.Unmarshal(unencryptedData, &sessionsJSON)
	if err != nil {
		return nil, errors.Wrap(err, "invalid export json")
	}
	return sessionsJSON, nil
}

func (mach *OlmMachine) importExportedRoomKey(session ExportedSession) error {
	if session.Algorithm != id.AlgorithmMegolmV1 {
		return ErrInvalidExportedAlgorithm
	}

	igsInternal, err := olm.InboundGroupSessionImport([]byte(session.SessionKey))
	if err != nil {
		return errors.Wrap(err, "failed to import session")
	} else if igsInternal.ID() != session.SessionID {
		return ErrMismatchingExportedSessionID
	}
	igs := &InboundGroupSession{
		Internal:   *igsInternal,
		SigningKey: session.SenderClaimedKeys.Ed25519,
		SenderKey:  session.SenderKey,
		RoomID:     session.RoomID,
		// TODO should we add something here to mark the signing key as unverified like key requests do?
		ForwardingChains: session.ForwardingChains,
	}
	err = mach.CryptoStore.PutGroupSession(igs.RoomID, igs.SenderKey, igs.ID(), igs)
	if err != nil {
		return errors.Wrap(err, "failed to store imported session")
	}
	return nil
}

func (mach *OlmMachine) ImportKeys(passphrase string, data string) (int, error) {
	if !strings.HasPrefix(data, exportPrefix) || !strings.HasSuffix(data, exportSuffix) {
		return 0, ErrMissingExportPrefix
	}
	exportData, err := base64.StdEncoding.DecodeString(data[len(exportPrefix) : len(data)-len(exportPrefix)])
	if err != nil {
		return 0, err
	}
	sessions, err := decryptKeyExport(passphrase, exportData)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, session := range sessions {
		err := mach.importExportedRoomKey(session)
		if err != nil {
			mach.Log.Warn("Failed to import Megolm session %s/%s from file: %v", session.RoomID, session.SessionID, err)
		} else {
			mach.Log.Debug("Imported Megolm session %s/%s from file", session.RoomID, session.SessionID)
			count++
		}
	}
	return count, nil
}
