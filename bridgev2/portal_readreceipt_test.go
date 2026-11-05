// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/event"
)

type readReceiptTestConnector struct {
	NetworkConnector
	threadReadReceipts bool
}

func (c *readReceiptTestConnector) GetCapabilities() *NetworkGeneralCapabilities {
	return &NetworkGeneralCapabilities{ThreadReadReceipts: c.threadReadReceipts}
}

type readReceiptTestClient struct {
	NetworkAPI
	handled int
}

func (c *readReceiptTestClient) HandleMatrixReadReceipt(context.Context, *MatrixReadReceipt) error {
	c.handled++
	return nil
}

func TestIsThreadScopedReceipt(t *testing.T) {
	assert.False(t, isThreadScopedReceipt(event.ReadReceipt{}))
	assert.False(t, isThreadScopedReceipt(event.ReadReceipt{ThreadID: event.ReadReceiptThreadMain}))
	assert.True(t, isThreadScopedReceipt(event.ReadReceipt{ThreadID: "$root"}))
}

func TestHandleMatrixReadReceipt_DropsThreadReceiptWithoutCapability(t *testing.T) {
	// A receipt that isn't dropped reaches FindPreferredLogin, which panics on the empty bridge.
	portal := &Portal{Bridge: &Bridge{Network: &readReceiptTestConnector{}}}
	portal.handleMatrixReadReceipt(context.Background(), &User{User: &database.User{}}, "$reply", event.ReadReceipt{ThreadID: "$root"})
}

func TestCallReadReceiptHandler_ThreadReceiptKeepsChatState(t *testing.T) {
	// Saving LastRead or starting disappearing timers would panic on the empty bridge.
	portal := &Portal{Bridge: &Bridge{}}
	client := &readReceiptTestClient{}
	portal.callReadReceiptHandler(context.Background(), nil, client, &MatrixReadReceipt{
		Portal:  portal,
		EventID: "$reply",
		Receipt: event.ReadReceipt{ThreadID: "$root"},
	}, &database.UserPortal{})
	assert.Equal(t, 1, client.handled)
}
