// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, you can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"

	"maunium.net/go/mautrix"
)

// GetOrCreateBeeperStreamSender returns the cached Beeper stream sender for the bot client.
func (br *Bridge) GetOrCreateBeeperStreamSender() *mautrix.BeeperStreamSender {
	transport, err := br.GetBeeperStreamTransport(context.Background())
	if err != nil {
		return nil
	}
	sender, _ := transport.(*mautrix.BeeperStreamSender)
	return sender
}

// GetBeeperStreamTransport returns the bridge's Beeper stream transport if the matrix
// connector supports it.
func (br *Bridge) GetBeeperStreamTransport(ctx context.Context) (mautrix.BeeperStreamTransport, error) {
	provider, ok := br.Matrix.(MatrixConnectorWithBeeperStreamTransport)
	if !ok {
		return nil, fmt.Errorf("matrix connector does not provide beeper stream transport")
	}
	return provider.GetBeeperStreamTransport(ctx)
}
