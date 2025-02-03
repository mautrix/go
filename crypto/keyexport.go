// Copyright (c) 2025 Tulir Asokan
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
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exbytes"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/random"
	"golang.org/x/crypto/pbkdf2"

	"maunium.net/go/mautrix/id"
)

var ErrNoSessionsForExport = errors.New("no sessions provided for export")

type SenderClaimedKeys struct {
	Ed25519 id.Ed25519 `json:"ed25519"`
}

type ExportedSession struct {
	Algorithm         id.Algorithm      `json:"algorithm"`
	ForwardingChains  []string          `json:"forwarding_curve25519_key_chain"`
	RoomID            id.RoomID         `json:"room_id"`
	SenderKey         id.SenderKey      `json:"sender_key"`
	SenderClaimedKeys SenderClaimedKeys `json:"sender_claimed_keys"`
	SessionID         id.SessionID      `json:"session_id"`
	SessionKey        string            `json:"session_key"`
}

// The default number of pbkdf2 rounds to use when exporting keys
const defaultPassphraseRounds = 100000

const exportPrefix = "-----BEGIN MEGOLM SESSION DATA-----\n"
const exportSuffix = "-----END MEGOLM SESSION DATA-----\n"

// Only version 0x01 is currently specified in the spec
const exportVersion1 = 0x01

// The standard for wrapping base64 is 76 bytes
const exportLineLengthLimit = 76

// Byte count for version + salt + iv + number of rounds
const exportHeaderLength = 1 + 16 + 16 + 4

// SHA-256 hash length
const exportHashLength = 32

func computeKey(passphrase string, salt []byte, rounds int) (encryptionKey, hashKey []byte) {
	key := pbkdf2.Key([]byte(passphrase), salt, rounds, 64, sha512.New)
	encryptionKey = key[:32]
	hashKey = key[32:]
	return
}

func makeExportIV() []byte {
	iv := random.Bytes(16)
	// Set bit 63 to zero
	iv[7] &= 0b11111110
	return iv
}

func makeExportKeys(passphrase string) (encryptionKey, hashKey, salt, iv []byte) {
	salt = random.Bytes(16)
	encryptionKey, hashKey = computeKey(passphrase, salt, defaultPassphraseRounds)
	iv = makeExportIV()
	return
}

func exportSessions(sessions []*InboundGroupSession) ([]*ExportedSession, error) {
	export := make([]*ExportedSession, len(sessions))
	var err error
	for i, session := range sessions {
		export[i], err = session.export()
		if err != nil {
			return nil, fmt.Errorf("failed to export session: %w", err)
		}
	}
	return export, nil
}

func exportSessionsJSON(sessions []*InboundGroupSession) ([]byte, error) {
	exportedSessions, err := exportSessions(sessions)
	if err != nil {
		return nil, err
	}
	return json.Marshal(exportedSessions)
}

func formatKeyExportData(data []byte) []byte {
	encodedLen := base64.StdEncoding.EncodedLen(len(data))
	outputLength := len(exportPrefix) +
		encodedLen + int(math.Ceil(float64(encodedLen)/exportLineLengthLimit)) +
		len(exportSuffix)
	output := make([]byte, 0, outputLength)
	outputWriter := (*exbytes.Writer)(&output)
	base64Writer := base64.NewEncoder(base64.StdEncoding, outputWriter)
	lineByteCount := base64.StdEncoding.DecodedLen(exportLineLengthLimit)
	exerrors.Must(outputWriter.WriteString(exportPrefix))
	for i := 0; i < len(data); i += lineByteCount {
		exerrors.Must(base64Writer.Write(data[i:min(i+lineByteCount, len(data))]))
		if i+lineByteCount >= len(data) {
			exerrors.PanicIfNotNil(base64Writer.Close())
		}
		exerrors.PanicIfNotNil(outputWriter.WriteByte('\n'))
	}
	exerrors.Must(outputWriter.WriteString(exportSuffix))
	if len(output) != outputLength {
		panic(fmt.Errorf("unexpected length %d / %d", len(output), outputLength))
	}
	return output
}

func ExportKeysIter(passphrase string, sessions dbutil.RowIter[*InboundGroupSession]) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 50*1024))
	enc := json.NewEncoder(buf)
	buf.WriteByte('[')
	err := sessions.Iter(func(session *InboundGroupSession) (bool, error) {
		exported, err := session.export()
		if err != nil {
			return false, err
		}
		err = enc.Encode(exported)
		if err != nil {
			return false, err
		}
		buf.WriteByte(',')
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	output := buf.Bytes()
	if len(output) == 1 {
		return nil, ErrNoSessionsForExport
	}
	output[len(output)-1] = ']' // Replace the last comma with a closing bracket
	return EncryptKeyExport(passphrase, output)
}

// ExportKeys exports the given Megolm sessions with the format specified in the Matrix spec.
// See https://spec.matrix.org/v1.2/client-server-api/#key-exports
func ExportKeys(passphrase string, sessions []*InboundGroupSession) ([]byte, error) {
	if len(sessions) == 0 {
		return nil, ErrNoSessionsForExport
	}
	// Export all the given sessions and put them in JSON
	unencryptedData, err := exportSessionsJSON(sessions)
	if err != nil {
		return nil, err
	}
	return EncryptKeyExport(passphrase, unencryptedData)
}

func EncryptKeyExport(passphrase string, unencryptedData json.RawMessage) ([]byte, error) {
	// Make all the keys necessary for exporting
	encryptionKey, hashKey, salt, iv := makeExportKeys(passphrase)

	// The export data consists of:
	// 1 byte of export format version
	// 16 bytes of salt
	// 16 bytes of IV (initialization vector)
	// 4 bytes of the number of rounds
	// the encrypted export data
	// 32 bytes of the hash of all the data above

	exportData := make([]byte, exportHeaderLength+len(unencryptedData)+exportHashLength)
	dataWithoutHashLength := len(exportData) - exportHashLength

	// Create the header for the export data
	exportData[0] = exportVersion1
	copy(exportData[1:17], salt)
	copy(exportData[17:33], iv)
	binary.BigEndian.PutUint32(exportData[33:37], defaultPassphraseRounds)

	// Encrypt data with AES-256-CTR
	block, _ := aes.NewCipher(encryptionKey)
	cipher.NewCTR(block, iv).XORKeyStream(exportData[exportHeaderLength:dataWithoutHashLength], unencryptedData)

	// Hash all the data with HMAC-SHA256 and put it at the end
	mac := hmac.New(sha256.New, hashKey)
	mac.Write(exportData[:dataWithoutHashLength])
	mac.Sum(exportData[:dataWithoutHashLength])

	// Format the export (prefix, base64'd exportData, suffix) and return
	return formatKeyExportData(exportData), nil
}
