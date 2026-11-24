// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix"
)

// sendLegacyBackfill skips a message when sendConvertedMessage fails with an error the homeserver will
// refuse again, and aborts on anything else. This checks the classification on errors shaped like the
// ones sendConvertedMessage returns: per-part errors wrapped with %w and joined.
func TestBlockBubblingEventError_SendConvertedMessageShape(t *testing.T) {
	forbidden := mautrix.HTTPError{
		RespError: ptrTo(mautrix.MForbidden.WithMessage("user_level (0) < send_level (50)")),
	}
	joined := errors.Join(fmt.Errorf("failed to send message part to Matrix: %w", forbidden))
	assert.True(t, blockBubblingEventError(joined))

	transient := errors.Join(fmt.Errorf("failed to send message part to Matrix: %w", errors.New("connection refused")))
	assert.False(t, blockBubblingEventError(transient))

	assert.False(t, blockBubblingEventError(errors.Join(context.Canceled)))
}

func ptrTo[T any](v T) *T { return &v }
