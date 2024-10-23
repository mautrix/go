// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"bytes"
	"encoding/json"
	"errors"

	"maunium.net/go/mautrix/id"
)

// Membership is an enum specifying the membership state of a room member.
type Membership string

func (ms Membership) IsInviteOrJoin() bool {
	return ms == MembershipJoin || ms == MembershipInvite
}

func (ms Membership) IsLeaveOrBan() bool {
	return ms == MembershipLeave || ms == MembershipBan
}

// The allowed membership states as specified in spec section 10.5.5.
const (
	MembershipJoin   Membership = "join"
	MembershipLeave  Membership = "leave"
	MembershipInvite Membership = "invite"
	MembershipBan    Membership = "ban"
	MembershipKnock  Membership = "knock"
)

// MemberEventContent represents the content of a m.room.member state event.
// https://spec.matrix.org/v1.2/client-server-api/#mroommember
type MemberEventContent struct {
	Membership       Membership          `json:"membership"`
	AvatarURL        id.ContentURIString `json:"avatar_url,omitempty"`
	Displayname      string              `json:"displayname,omitempty"`
	IsDirect         bool                `json:"is_direct,omitempty"`
	ThirdPartyInvite *ThirdPartyInvite   `json:"third_party_invite,omitempty"`
	Reason           string              `json:"reason,omitempty"`
}

type StandardProfile struct {
	Displayname string              `json:"displayname,omitempty"`
	AvatarURL   id.ContentURIString `json:"avatar_url,omitempty"`
}

type ExtendedProfile[T any] struct {
	StandardProfile
	Extra T
}

func (ep *ExtendedProfile[T]) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(ep.StandardProfile)
	if err != nil {
		return nil, err
	}
	extraData, err := json.Marshal(ep.Extra)
	if err != nil {
		return nil, err
	}
	if len(extraData) == 0 || bytes.Equal(extraData, []byte("{}")) || bytes.Equal(extraData, []byte("null")) {
		return data, nil
	} else if extraData[0] != '{' || extraData[len(extraData)-1] != '}' {
		return nil, errors.New("unexpected type marshaling profile extra data: not an object")
	}
	data[len(data)-1] = ','
	data = append(data, extraData[1:]...)
	return data, nil
}

func (ep *ExtendedProfile[T]) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &ep.StandardProfile)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &ep.Extra)
}

type ThirdPartyInvite struct {
	DisplayName string `json:"display_name"`
	Signed      struct {
		Token      string          `json:"token"`
		Signatures json.RawMessage `json:"signatures"`
		MXID       string          `json:"mxid"`
	}
}
