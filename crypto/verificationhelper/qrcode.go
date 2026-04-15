// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package verificationhelper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"go.mau.fi/util/random"

	"maunium.net/go/mautrix/id"
)

var (
	ErrInvalidQRCodeHeader  = errors.New("invalid QR code header")
	ErrUnknownQRCodeVersion = errors.New("invalid QR code version")
	ErrInvalidQRCodeMode    = errors.New("invalid QR code mode")
	ErrInvalidQRCodeLength  = errors.New("QR data too short")
)

type QRCodeMode byte

const (
	QRCodeModeCrossSigning                    QRCodeMode = 0x00
	QRCodeModeSelfVerifyingMasterKeyTrusted   QRCodeMode = 0x01
	QRCodeModeSelfVerifyingMasterKeyUntrusted QRCodeMode = 0x02
)

const MinQRSharedSecretLength = 8

type QRCode struct {
	Mode          QRCodeMode
	TransactionID id.VerificationTransactionID
	Key1, Key2    [32]byte
	SharedSecret  []byte
}

func NewQRCode(mode QRCodeMode, txnID id.VerificationTransactionID, key1, key2 [32]byte) *QRCode {
	return &QRCode{
		Mode:          mode,
		TransactionID: txnID,
		Key1:          key1,
		Key2:          key2,
		SharedSecret:  random.Bytes(16),
	}
}

const qrHeaderString = "MATRIX"
const minQRLength = len(qrHeaderString) + 4 + 2*32 + MinQRSharedSecretLength

var qrHeader = []byte(qrHeaderString)

// NewQRCodeFromBytes parses the bytes from a QR code scan as defined in
// [Section 11.12.2.4.1] of the Spec.
//
// [Section 11.12.2.4.1]: https://spec.matrix.org/v1.9/client-server-api/#qr-code-format
func NewQRCodeFromBytes(data []byte) (*QRCode, error) {
	if !bytes.HasPrefix(data, qrHeader) {
		return nil, ErrInvalidQRCodeHeader
	}
	if len(data) > 6 && data[6] != 0x02 {
		return nil, ErrUnknownQRCodeVersion
	}
	if len(data) < minQRLength {
		return nil, fmt.Errorf("%w: expected at least %d bytes, got %d", ErrInvalidQRCodeLength, minQRLength, len(data))
	}
	if data[7] != 0x00 && data[7] != 0x01 && data[7] != 0x02 {
		return nil, ErrInvalidQRCodeMode
	}
	transactionIDLength := binary.BigEndian.Uint16(data[8:10])
	if len(data) < int(10+transactionIDLength+64) {
		return nil, fmt.Errorf("%w for transaction ID: expected at least %d bytes, got %d", ErrInvalidQRCodeLength, 10+transactionIDLength+64, len(data))
	}
	transactionID := data[10 : 10+transactionIDLength]

	var key1, key2 [32]byte
	copy(key1[:], data[10+transactionIDLength:10+transactionIDLength+32])
	copy(key2[:], data[10+transactionIDLength+32:10+transactionIDLength+64])
	sharedSecret := data[10+transactionIDLength+64:]
	if len(sharedSecret) < MinQRSharedSecretLength {
		return nil, fmt.Errorf("%w: expected at least %d bytes for shared secret, got %d", ErrInvalidQRCodeLength, MinQRSharedSecretLength, len(sharedSecret))
	}

	return &QRCode{
		Mode:          QRCodeMode(data[7]),
		TransactionID: id.VerificationTransactionID(transactionID),
		Key1:          key1,
		Key2:          key2,
		SharedSecret:  sharedSecret,
	}, nil
}

// Bytes returns the bytes that need to be encoded in the QR code as defined in
// [Section 11.12.2.4.1] of the Spec.
//
// [Section 11.12.2.4.1]: https://spec.matrix.org/v1.9/client-server-api/#qr-code-format
func (q *QRCode) Bytes() []byte {
	if q == nil {
		return nil
	}

	var buf bytes.Buffer
	buf.WriteString("MATRIX")   // Header
	buf.WriteByte(0x02)         // Version
	buf.WriteByte(byte(q.Mode)) // Mode

	// Transaction ID length + Transaction ID
	buf.Write(binary.BigEndian.AppendUint16(nil, uint16(len(q.TransactionID.String()))))
	buf.WriteString(q.TransactionID.String())

	buf.Write(q.Key1[:])      // Key 1
	buf.Write(q.Key2[:])      // Key 2
	buf.Write(q.SharedSecret) // Shared secret
	return buf.Bytes()
}
