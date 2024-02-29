// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/element-hq/mautrix-go/crypto/olm"
	"github.com/element-hq/mautrix-go/id"
)

var (
	ErrMissingExportPrefix          = errors.New("invalid Matrix key export: missing prefix")
	ErrMissingExportSuffix          = errors.New("invalid Matrix key export: missing suffix")
	ErrUnsupportedExportVersion     = errors.New("unsupported Matrix key export format version")
	ErrMismatchingExportHash        = errors.New("mismatching hash; incorrect passphrase?")
	ErrInvalidExportedAlgorithm     = errors.New("session has unknown algorithm")
	ErrMismatchingExportedSessionID = errors.New("imported session has different ID than expected")
)

var exportPrefixBytes, exportSuffixBytes = []byte(exportPrefix), []byte(exportSuffix)

func decodeKeyExport(data []byte) ([]byte, error) {
	// If the valid prefix and suffix aren't there, it's probably not a Matrix key export
	if !bytes.HasPrefix(data, exportPrefixBytes) {
		return nil, ErrMissingExportPrefix
	} else if !bytes.HasSuffix(data, exportSuffixBytes) {
		return nil, ErrMissingExportSuffix
	}
	// Remove the prefix and suffix, we don't care about them anymore
	data = data[len(exportPrefix) : len(data)-len(exportSuffix)]

	// Allocate space for the decoded data. Ignore newlines when counting the length
	exportData := make([]byte, base64.StdEncoding.DecodedLen(len(data)-bytes.Count(data, []byte{'\n'})))
	n, err := base64.StdEncoding.Decode(exportData, data)
	if err != nil {
		return nil, err
	}

	return exportData[:n], nil
}

func decryptKeyExport(passphrase string, exportData []byte) ([]ExportedSession, error) {
	if exportData[0] != exportVersion1 {
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
	encryptionKey, hashKey := computeKey(passphrase, salt, int(passphraseRounds))

	// Compute and verify the hash. If it doesn't match, the passphrase is probably wrong
	mac := hmac.New(sha256.New, hashKey)
	mac.Write(exportData[:dataWithoutHashLength])
	if !bytes.Equal(hash, mac.Sum(nil)) {
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
		return nil, fmt.Errorf("invalid export json: %w", err)
	}
	return sessionsJSON, nil
}

func (mach *OlmMachine) importExportedRoomKey(ctx context.Context, session ExportedSession) (bool, error) {
	if session.Algorithm != id.AlgorithmMegolmV1 {
		return false, ErrInvalidExportedAlgorithm
	}

	igsInternal, err := olm.InboundGroupSessionImport([]byte(session.SessionKey))
	if err != nil {
		return false, fmt.Errorf("failed to import session: %w", err)
	} else if igsInternal.ID() != session.SessionID {
		return false, ErrMismatchingExportedSessionID
	}
	igs := &InboundGroupSession{
		Internal:   *igsInternal,
		SigningKey: session.SenderClaimedKeys.Ed25519,
		SenderKey:  session.SenderKey,
		RoomID:     session.RoomID,
		// TODO should we add something here to mark the signing key as unverified like key requests do?
		ForwardingChains: session.ForwardingChains,

		ReceivedAt: time.Now().UTC(),
	}
	existingIGS, _ := mach.CryptoStore.GetGroupSession(ctx, igs.RoomID, igs.SenderKey, igs.ID())
	if existingIGS != nil && existingIGS.Internal.FirstKnownIndex() <= igs.Internal.FirstKnownIndex() {
		// We already have an equivalent or better session in the store, so don't override it.
		return false, nil
	}
	err = mach.CryptoStore.PutGroupSession(ctx, igs.RoomID, igs.SenderKey, igs.ID(), igs)
	if err != nil {
		return false, fmt.Errorf("failed to store imported session: %w", err)
	}
	mach.markSessionReceived(igs.ID())
	return true, nil
}

// ImportKeys imports data that was exported with the format specified in the Matrix spec.
// See https://spec.matrix.org/v1.2/client-server-api/#key-exports
func (mach *OlmMachine) ImportKeys(ctx context.Context, passphrase string, data []byte) (int, int, error) {
	exportData, err := decodeKeyExport(data)
	if err != nil {
		return 0, 0, err
	}
	sessions, err := decryptKeyExport(passphrase, exportData)
	if err != nil {
		return 0, 0, err
	}

	count := 0
	for _, session := range sessions {
		log := mach.Log.With().
			Str("room_id", session.RoomID.String()).
			Str("session_id", session.SessionID.String()).
			Logger()
		imported, err := mach.importExportedRoomKey(ctx, session)
		if err != nil {
			if ctx.Err() != nil {
				return count, len(sessions), ctx.Err()
			}
			log.Error().Err(err).Msg("Failed to import Megolm session from file")
		} else if imported {
			log.Debug().Msg("Imported Megolm session from file")
			count++
		} else {
			log.Debug().Msg("Skipped Megolm session which is already in the store")
		}
	}
	return count, len(sessions), nil
}
