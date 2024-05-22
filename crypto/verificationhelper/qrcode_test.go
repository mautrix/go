// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package verificationhelper_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/id"
)

func TestQRCode_Roundtrip(t *testing.T) {
	var key1, key2 [32]byte
	copy(key1[:], bytes.Repeat([]byte{0x01}, 32))
	copy(key2[:], bytes.Repeat([]byte{0x02}, 32))
	txnID := id.VerificationTransactionID(strings.Repeat("a", 20))
	qrCode := verificationhelper.NewQRCode(verificationhelper.QRCodeModeCrossSigning, txnID, key1, key2)

	encoded := qrCode.Bytes()
	decoded, err := verificationhelper.NewQRCodeFromBytes(encoded)
	require.NoError(t, err)

	assert.Equal(t, verificationhelper.QRCodeModeCrossSigning, decoded.Mode)
	assert.EqualValues(t, txnID, decoded.TransactionID)
	assert.Equal(t, key1, decoded.Key1)
	assert.Equal(t, key2, decoded.Key2)
}

func TestQRCodeDecode(t *testing.T) {
	testCases := []struct {
		b64          string
		txnID        string
		key1         string
		key2         string
		sharedSecret string
	}{
		{
			"TUFUUklYAgEAIEduQWVDdnRXanpNT1ZXUVRrdDM1WVJVcnVqbVJQYzhhGDJ8w4zCpsK1wqdQV2cZXsOvwqDCmMKdNsOtehAuGD5Ow4TDgUUMwq4ZeMKZBsKSwpTCjsK3WcKWwq3DvXBqEcK6wqkpw48NwrjCiGdbw7MBwrBjLsKlw7Ngw4IEw6NyfXwdwrbCusKBHsKZwrh/Cg==",
			"GnAeCvtWjzMOVWQTkt35YRUrujmRPc8a",
			"GDJ8w4zCpsK1wqdQV2cZXsOvwqDCmMKdNsOtehAuGD4=",
			"TsOEw4FFDMKuGXjCmQbCksKUwo7Ct1nClsKtw71wahE=",
			"wrrCqSnDjw3CuMKIZ1vDswHCsGMuwqXDs2DDggTDo3J9fB3CtsK6woEewpnCuH8K",
		},
		{
			"TUFUUklYAgEAIGM1YjljNzE3ZWIzYjRmYzBiZDhhZjA0MDQ4NDY5MDdle4oLkpUdO1cTu5M3K3B4BlnpxtAbVgXCuQKOIqMmt+xAjVvaEXF39X0z5waRY9UE0b5PKiWvOBSJHEGkxX28Y2OEDLIWP/kCVUlyXXENlj0=",
			"c5b9c717eb3b4fc0bd8af0404846907e",
			"e4oLkpUdO1cTu5M3K3B4BlnpxtAbVgXCuQKOIqMmt+w=",
			"QI1b2hFxd/V9M+cGkWPVBNG+TyolrzgUiRxBpMV9vGM=",
			"Y4QMshY/+QJVSXJdcQ2WPQ==",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.b64, func(t *testing.T) {
			qrcodeData, err := base64.StdEncoding.DecodeString(tc.b64)
			require.NoError(t, err)
			expectedKey1, err := base64.StdEncoding.DecodeString(tc.key1)
			require.NoError(t, err)
			expectedKey2, err := base64.StdEncoding.DecodeString(tc.key2)
			require.NoError(t, err)
			expectedSharedSecret, err := base64.StdEncoding.DecodeString(tc.sharedSecret)
			require.NoError(t, err)

			decoded, err := verificationhelper.NewQRCodeFromBytes(qrcodeData)
			require.NoError(t, err)
			assert.Equal(t, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted, decoded.Mode)
			assert.EqualValues(t, tc.txnID, decoded.TransactionID)
			assert.EqualValues(t, expectedKey1, decoded.Key1)
			assert.EqualValues(t, expectedKey2, decoded.Key2)
			assert.EqualValues(t, expectedSharedSecret, decoded.SharedSecret)
		})
	}
}
