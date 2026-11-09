// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"testing"

	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

func TestShouldCreatePortalForRemoteEvent(t *testing.T) {
	allowedKey := networkid.PortalKey{ID: networkid.PortalID("allowed")}
	deniedKey := networkid.PortalKey{ID: networkid.PortalID("denied")}
	source := networkid.UserLoginID("login")
	filter := &bridgeconfig.PortalCreateFilter{
		Mode: bridgeconfig.PortalCreateFilterModeAllow,
		List: []*bridgeconfig.PortalCreateFilterItem{{ID: allowedKey.ID}},
	}

	tests := []struct {
		name        string
		key         networkid.PortalKey
		portalExist bool
		want        bool
	}{
		{name: "allowed new portal", key: allowedKey, want: true},
		{name: "disallowed new portal", key: deniedKey, want: false},
		{name: "existing disallowed portal", key: deniedKey, portalExist: true, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := shouldCreatePortalForRemoteEvent(filter, source, test.key, test.portalExist)
			if got != test.want {
				t.Fatalf("shouldCreatePortalForRemoteEvent() = %v, want %v", got, test.want)
			}
		})
	}
}
