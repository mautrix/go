// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"

	"maunium.net/go/mautrix/id"
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

const defaultPassphraseRounds = 100000

func computeKey(passphrase string, salt []byte, rounds int) (encryptionKey, hashKey []byte) {
	key := pbkdf2.Key([]byte(passphrase), salt, rounds, 64, sha512.New)
	encryptionKey = key[:32]
	hashKey = key[32:]
	return
}

func makeExportIV() ([]byte, error) {
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	// Set bit 63 to zero
	iv[7] &= 0b11111110
	return iv, nil
}

func makeExportKeys(passphrase string) (encryptionKey, hashKey, salt, iv []byte, err error) {
	salt = make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		return
	}

	encryptionKey, hashKey = computeKey(passphrase, salt, defaultPassphraseRounds)

	iv, err = makeExportIV()
	return
}

func exportSessions(sessions []*InboundGroupSession) ([]ExportedSession, error) {
	export := make([]ExportedSession, len(sessions))
	for i, session := range sessions {
		key, err := session.Internal.Export(session.Internal.FirstKnownIndex())
		if err != nil {
			return nil, errors.Wrap(err, "failed to export session")
		}
		export[i] = ExportedSession{
			Algorithm:         id.AlgorithmMegolmV1,
			ForwardingChains:  session.ForwardingChains,
			RoomID:            session.RoomID,
			SenderKey:         session.SenderKey,
			SenderClaimedKeys: SenderClaimedKeys{},
			SessionID:         session.ID(),
			SessionKey:        key,
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

const exportPrefix = "-----BEGIN MEGOLM SESSION DATA-----"
const exportSuffix = "-----END MEGOLM SESSION DATA-----"
const exportLineLengthLimit = 76
const exportHeaderLength = 1 + 16 + 16 + 4
const exportHashLength = 32

func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}

func formatKeyExportData(data []byte) string {
	dataStr := base64.StdEncoding.EncodeToString(data)
	// Base64 lines + prefix + suffix + empty line at end
	lines := make([]string, int(math.Ceil(float64(len(dataStr)) / exportLineLengthLimit)) + 3)
	lines[0] = exportPrefix
	line := 1
	for ptr := 0; ptr < len(dataStr); ptr += exportLineLengthLimit {
		lines[line] = dataStr[ptr:min(ptr+exportLineLengthLimit, len(dataStr))]
		line++
	}
	lines[len(lines)-2] = exportSuffix
	return strings.Join(lines, "\n")
}

// ExportKeys exports the given Megolm sessions with the format specified in the Matrix spec.
// See https://matrix.org/docs/spec/client_server/r0.6.1#key-exports
func ExportKeys(passphrase string, sessions []*InboundGroupSession) (string, error) {
	// Make all the keys necessary for exporting
	encryptionKey, hashKey, salt, iv, err := makeExportKeys(passphrase)
	if err != nil {
		return "", err
	}
	// Export all the given sessions and put them in JSON
	unencryptedData, err := exportSessionsJSON(sessions)
	if err != nil {
		return "", err
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
	exportData[0] = 0x01
	copy(exportData[1:17], salt)
	copy(exportData[17:33], iv)
	binary.BigEndian.PutUint32(exportData[33:37], defaultPassphraseRounds)

	// Encrypt data with AES-256-CTR
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	cipher.NewCTR(block, iv).XORKeyStream(exportData[exportHeaderLength:dataWithoutHashLength], unencryptedData)

	// Hash all the data with HMAC-SHA256 and put it at the end
	mac := hmac.New(sha256.New, hashKey)
	mac.Write(exportData[:dataWithoutHashLength])
	mac.Sum(exportData[:dataWithoutHashLength])

	// Format the export (prefix, base64'd exportData, suffix) and return
	return formatKeyExportData(exportData), nil
}