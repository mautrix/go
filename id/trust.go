// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package id

import (
	"fmt"
	"strings"
)

// TrustState determines how trusted a device is.
type TrustState int

const (
	TrustStateBlacklisted        TrustState = -100
	TrustStateUnset              TrustState = 0
	TrustStateUnknownDevice      TrustState = 10
	TrustStateForwarded          TrustState = 20
	TrustStateCrossSigned        TrustState = 100
	TrustStateCrossSignedTrusted TrustState = 200
	TrustStateVerified           TrustState = 300
	TrustStateInvalid            TrustState = (1 << 31) - 1
)

func (ts *TrustState) UnmarshalText(data []byte) error {
	strData := string(data)
	state := ParseTrustState(strData)
	if state == TrustStateInvalid {
		return fmt.Errorf("invalid trust state %q", strData)
	}
	*ts = state
	return nil
}

func (ts *TrustState) MarshalText() ([]byte, error) {
	return []byte(ts.String()), nil
}

func ParseTrustState(val string) TrustState {
	switch strings.ToLower(val) {
	case "blacklisted":
		return TrustStateBlacklisted
	case "unverified":
		return TrustStateUnset
	case "unknown-device", "unknown device":
		return TrustStateUnknownDevice
	case "forwarded":
		return TrustStateForwarded
	case "cross-signed", "tofu", "verified (via cross-signing, tofu)":
		return TrustStateCrossSigned
	case "cross-signed-trusted", "verified (via cross-signing, trusted user)":
		return TrustStateCrossSignedTrusted
	case "verified":
		return TrustStateVerified
	default:
		return TrustStateInvalid
	}
}

func (ts TrustState) String() string {
	switch ts {
	case TrustStateBlacklisted:
		return "blacklisted"
	case TrustStateUnset:
		return "unverified"
	case TrustStateUnknownDevice:
		return "unknown-device"
	case TrustStateForwarded:
		return "forwarded"
	case TrustStateCrossSigned:
		return "cross-signed"
	case TrustStateCrossSignedTrusted:
		return "cross-signed-trusted"
	case TrustStateVerified:
		return "verified"
	default:
		return "invalid"
	}
}

func (ts TrustState) Description() string {
	switch ts {
	case TrustStateBlacklisted:
		return "blacklisted"
	case TrustStateUnset:
		return "unverified"
	case TrustStateUnknownDevice:
		return "unknown device"
	case TrustStateForwarded:
		return "forwarded"
	case TrustStateCrossSigned:
		return "cross-signed, tofu"
	case TrustStateCrossSignedTrusted:
		return "cross-signed, trusted user"
	case TrustStateVerified:
		return "verified locally"
	default:
		return fmt.Sprintf("unknown %d", ts)
	}
}
