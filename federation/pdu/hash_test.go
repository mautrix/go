// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package pdu_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mau.fi/util/exerrors"
)

func TestPDU_CalculateContentHash(t *testing.T) {
	for _, test := range testPDUs {
		if test.redacted {
			continue
		}
		t.Run(test.name, func(t *testing.T) {
			parsed := parsePDU(test.pdu)
			contentHash := exerrors.Must(parsed.CalculateContentHash())
			assert.Equal(
				t,
				base64.RawStdEncoding.EncodeToString(parsed.Hashes.SHA256),
				base64.RawStdEncoding.EncodeToString(contentHash[:]),
			)
		})
	}
}

func TestPDU_VerifyContentHash(t *testing.T) {
	for _, test := range testPDUs {
		if test.redacted {
			continue
		}
		t.Run(test.name, func(t *testing.T) {
			parsed := parsePDU(test.pdu)
			assert.True(t, parsed.VerifyContentHash())
		})
	}
}

func TestPDU_GetEventID(t *testing.T) {
	for _, test := range testPDUs {
		t.Run(test.name, func(t *testing.T) {
			gotEventID := exerrors.Must(parsePDU(test.pdu).GetEventID(test.roomVersion))
			assert.Equal(t, test.eventID, gotEventID)
		})
	}
}
