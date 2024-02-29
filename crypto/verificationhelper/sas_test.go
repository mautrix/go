// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package verificationhelper_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/element-hq/mautrix-go/crypto/verificationhelper"
)

func TestBrokenB64Encode(t *testing.T) {
	// See example from the PR that fixed the issue:
	// https://gitlab.matrix.org/matrix-org/olm/-/merge_requests/16
	input := []byte{
		121, 105, 187, 19, 37, 94, 119, 248, 224, 34, 94, 29, 157, 5,
		15, 230, 246, 115, 236, 217, 80, 78, 56, 200, 80, 200, 82, 158,
		168, 179, 10, 230,
	}

	b64 := verificationhelper.BrokenB64Encode(input)
	assert.Equal(t, "eWm7NyVeVmXgbVhnYlZobllsWm9ibGxzV205aWJHeHo", b64)
}
