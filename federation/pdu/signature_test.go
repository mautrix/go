// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

func TestPDU_VerifySignature(t *testing.T) {
	for _, test := range testPDUs {
		t.Run(test.name, func(t *testing.T) {
			parsed := parsePDU(test.pdu)
			err := parsed.VerifySignature(test.roomVersion, test.serverName, test.getKey)
			assert.NoError(t, err)
		})
	}
}

func TestPDU_VerifySignature_Fail_NoKey(t *testing.T) {
	test := roomV12MessageTestPDU
	parsed := parsePDU(test.pdu)
	err := parsed.VerifySignature(test.roomVersion, test.serverName, func(serverName string, keyID id.KeyID, minValidUntil time.Time) (key id.SigningKey, validUntil time.Time, err error) {
		return
	})
	assert.Error(t, err)
}

func TestPDU_VerifySignature_V4ExpiredKey(t *testing.T) {
	test := roomV4MessageTestPDU
	parsed := parsePDU(test.pdu)
	err := parsed.VerifySignature(test.roomVersion, test.serverName, func(serverName string, keyID id.KeyID, minValidUntil time.Time) (key id.SigningKey, validUntil time.Time, err error) {
		key = test.keys[keyID].key
		validUntil = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		return
	})
	assert.NoError(t, err)
}

func TestPDU_VerifySignature_V12ExpiredKey(t *testing.T) {
	test := roomV12MessageTestPDU
	parsed := parsePDU(test.pdu)
	err := parsed.VerifySignature(test.roomVersion, test.serverName, func(serverName string, keyID id.KeyID, minValidUntil time.Time) (key id.SigningKey, validUntil time.Time, err error) {
		key = test.keys[keyID].key
		validUntil = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		return
	})
	assert.Error(t, err)
}

func TestPDU_VerifySignature_V12InvalidSignature(t *testing.T) {
	test := roomV12MessageTestPDU
	parsed := parsePDU(test.pdu)
	for _, sigs := range parsed.Signatures {
		for key := range sigs {
			sigs[key] = sigs[key][:len(sigs[key])-3] + "ABC"
		}
	}
	err := parsed.VerifySignature(test.roomVersion, test.serverName, test.getKey)
	assert.Error(t, err)
}

func TestPDU_Sign(t *testing.T) {
	pubKey, privKey := exerrors.Must2(ed25519.GenerateKey(nil))
	evt := &pdu.PDU{
		AuthEvents:     []id.EventID{"$gCzdJUVV93Qory0x7p_PLG5UUiDjPJNe1H12qbHTuFA", "$hyeL_nU_L3tsZ2dtZZpAHk0Skv-PqFQIipuII_By584"},
		Content:        jsontext.Value(`{"msgtype":"m.text","body":"Hello, world!"}`),
		Depth:          123,
		OriginServerTS: 1755384351627,
		PrevEvents:     []id.EventID{"$gCzdJUVV93Qory0x7p_PLG5UUiDjPJNe1H12qbHTuFA"},
		RoomID:         "!mauT12AzsoqxV7Abvy_ApA-HNPK1LcT4GbP70_AOPyQ",
		Sender:         "@tulir:example.com",
		Type:           "m.room.message",
	}
	err := evt.Sign(id.RoomV12, "example.com", "ed25519:rand", privKey)
	require.NoError(t, err)
	err = evt.VerifySignature(id.RoomV11, "example.com", func(serverName string, keyID id.KeyID, minValidUntil time.Time) (key id.SigningKey, validUntil time.Time, err error) {
		if serverName == "example.com" && keyID == "ed25519:rand" {
			key = id.SigningKey(base64.RawStdEncoding.EncodeToString(pubKey))
			validUntil = time.Now()
		}
		return
	})
	require.NoError(t, err)

}
