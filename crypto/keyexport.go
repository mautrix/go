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
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"

	"golang.org/x/crypto/pbkdf2"

	"github.com/element-hq/mautrix-go/crypto/olm"
	"github.com/element-hq/mautrix-go/id"
)

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
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		panic(olm.NotEnoughGoRandom)
	}
	// Set bit 63 to zero
	iv[7] &= 0b11111110
	return iv
}

func makeExportKeys(passphrase string) (encryptionKey, hashKey, salt, iv []byte) {
	salt = make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(olm.NotEnoughGoRandom)
	}

	encryptionKey, hashKey = computeKey(passphrase, salt, defaultPassphraseRounds)

	iv = makeExportIV()
	return
}

func exportSessions(sessions []*InboundGroupSession) ([]ExportedSession, error) {
	export := make([]ExportedSession, len(sessions))
	for i, session := range sessions {
		key, err := session.Internal.Export(session.Internal.FirstKnownIndex())
		if err != nil {
			return nil, fmt.Errorf("failed to export session: %w", err)
		}
		export[i] = ExportedSession{
			Algorithm:         id.AlgorithmMegolmV1,
			ForwardingChains:  session.ForwardingChains,
			RoomID:            session.RoomID,
			SenderKey:         session.SenderKey,
			SenderClaimedKeys: SenderClaimedKeys{},
			SessionID:         session.ID(),
			SessionKey:        string(key),
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

func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}

func formatKeyExportData(data []byte) []byte {
	base64Data := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(base64Data, data)

	// Prefix + data and newline for each 76 characters of data + suffix
	outputLength := len(exportPrefix) +
		len(base64Data) + int(math.Ceil(float64(len(base64Data))/exportLineLengthLimit)) +
		len(exportSuffix)

	var buf bytes.Buffer
	buf.Grow(outputLength)
	buf.WriteString(exportPrefix)
	for ptr := 0; ptr < len(base64Data); ptr += exportLineLengthLimit {
		buf.Write(base64Data[ptr:min(ptr+exportLineLengthLimit, len(base64Data))])
		buf.WriteRune('\n')
	}
	buf.WriteString(exportSuffix)
	if buf.Len() != buf.Cap() || buf.Len() != outputLength {
		panic(fmt.Errorf("unexpected length %d / %d / %d", buf.Len(), buf.Cap(), outputLength))
	}
	return buf.Bytes()
}

// ExportKeys exports the given Megolm sessions with the format specified in the Matrix spec.
// See https://spec.matrix.org/v1.2/client-server-api/#key-exports
func ExportKeys(passphrase string, sessions []*InboundGroupSession) ([]byte, error) {
	// Make all the keys necessary for exporting
	encryptionKey, hashKey, salt, iv := makeExportKeys(passphrase)
	// Export all the given sessions and put them in JSON
	unencryptedData, err := exportSessionsJSON(sessions)
	if err != nil {
		return nil, err
	}

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
