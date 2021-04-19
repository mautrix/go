// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

type CallHangupReason string

const (
	CallHangupICEFailed       CallHangupReason = "ice_failed"
	CallHangupInviteTimeout   CallHangupReason = "invite_timeout"
	CallHangupUserHangup      CallHangupReason = "user_hangup"
	CallHangupUserMediaFailed CallHangupReason = "user_media_failed"
	CallHangupUnknownError    CallHangupReason = "unknown_error"
)

type CallDataType string

const (
	CallDataTypeOffer  CallDataType = "offer"
	CallDataTypeAnswer CallDataType = "answer"
)

type CallData struct {
	SDP  string       `json:"sdp"`
	Type CallDataType `json:"type"`
}

type CallCandidate struct {
	Candidate     string `json:"candidate"`
	SDPMLineIndex int    `json:"sdpMLineIndex"`
	SDPMID        string `json:"sdpMid"`
}

type BaseCallEventContent struct {
	CallID  string `json:"call_id"`
	PartyID string `json:"party_id"`
	Version int    `json:"version"`
}

type CallInviteEventContent struct {
	BaseCallEventContent
	Lifetime int      `json:"lifetime"`
	Offer    CallData `json:"offer"`
}

type CallCandidatesEventContent struct {
	BaseCallEventContent
	Candidates []CallCandidate `json:"candidates"`
}

type CallRejectEventContent struct {
	BaseCallEventContent
}

type CallAnswerEventContent struct {
	BaseCallEventContent
	Answer CallData `json:"answer"`
}

type CallSelectAnswerEventContent struct {
	BaseCallEventContent
	SelectedPartyID string `json:"selected_party_id"`
}

type CallNegotiateEventContent struct {
	BaseCallEventContent
	Lifetime    int      `json:"lifetime"`
	Description CallData `json:"description"`
}

type CallHangupEventContent struct {
	BaseCallEventContent
	Reason CallHangupReason `json:"reason"`
}
