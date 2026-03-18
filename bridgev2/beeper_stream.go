// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"fmt"

	"maunium.net/go/mautrix"
)

// GetBeeperStreamTransport returns the bridge's Beeper stream transport if the matrix
// connector supports it.
func (br *Bridge) GetBeeperStreamTransport() (mautrix.BeeperStreamTransport, error) {
	provider, ok := br.Matrix.(MatrixConnectorWithBeeperStreamTransport)
	if !ok {
		return nil, fmt.Errorf("matrix connector does not provide beeper stream transport")
	}
	return provider.GetBeeperStreamTransport(), nil
}
