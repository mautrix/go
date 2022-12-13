// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/json"
	"fmt"
	"strconv"

	"maunium.net/go/mautrix/id"
)

type CallHangupReason string

const (
	CallHangupICEFailed        CallHangupReason = "ice_failed"
	CallHangupInviteTimeout    CallHangupReason = "invite_timeout"
	CallHangupUserHangup       CallHangupReason = "user_hangup"
	CallHangupUserMediaFailed  CallHangupReason = "user_media_failed"
	CallHangupKeepAliveTimeout CallHangupReason = "keep_alive_timeout"
	CallHangupUnknownError     CallHangupReason = "unknown_error"
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

type CallVersion string

func (cv *CallVersion) UnmarshalJSON(raw []byte) error {
	var numberVersion int
	err := json.Unmarshal(raw, &numberVersion)
	if err != nil {
		var stringVersion string
		err = json.Unmarshal(raw, &stringVersion)
		if err != nil {
			return fmt.Errorf("failed to parse CallVersion: %w", err)
		}
		*cv = CallVersion(stringVersion)
	} else {
		*cv = CallVersion(strconv.Itoa(numberVersion))
	}
	return nil
}

func (cv *CallVersion) MarshalJSON() ([]byte, error) {
	for _, char := range *cv {
		if char < '0' || char > '9' {
			// The version contains weird characters, return as string.
			return json.Marshal(string(*cv))
		}
	}
	// The version consists of only ASCII digits, return as an integer.
	return []byte(*cv), nil
}

func (cv *CallVersion) Int() (int, error) {
	return strconv.Atoi(string(*cv))
}

type BaseCallEventContent struct {
	CallID          string       `json:"call_id"`
	ConfID          string       `json:"conf_id"`
	PartyID         string       `json:"party_id"`
	Version         CallVersion  `json:"version"`
	DeviceID        id.DeviceID  `json:"device_id"`
	DestSessionID   id.SessionID `json:"dest_session_id"`
	SenderSessionID id.SessionID `json:"sender_session_id"`
}

type CallSDPStreamMetadataPurpose string

const (
	Usermedia   CallSDPStreamMetadataPurpose = "m.usermedia"
	Screenshare CallSDPStreamMetadataPurpose = "m.screenshare"
)

type CallSDPStreamMetadataTrack struct {
	Kind   string `json:"kind,omitempty"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
}

type CallSDPStreamMetadataTracks map[string]CallSDPStreamMetadataTrack

type CallSDPStreamMetadataObject struct {
	UserID     id.UserID                    `json:"user_id"`
	DeviceID   id.DeviceID                  `json:"device_id"`
	Purpose    CallSDPStreamMetadataPurpose `json:"purpose"`
	AudioMuted bool                         `json:"audio_muted"`
	VideoMuted bool                         `json:"video_muted"`
	Tracks     CallSDPStreamMetadataTracks  `json:"tracks"`
}

type CallSDPStreamMetadata map[string]CallSDPStreamMetadataObject

type CallInviteEventContent struct {
	BaseCallEventContent
	Lifetime          int                   `json:"lifetime"`
	Offer             CallData              `json:"offer"`
	SDPStreamMetadata CallSDPStreamMetadata `json:"org.matrix.msc3077.sdp_stream_metadata"`
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
	Answer            CallData              `json:"answer"`
	SDPStreamMetadata CallSDPStreamMetadata `json:"org.matrix.msc3077.sdp_stream_metadata"`
}

type CallSelectAnswerEventContent struct {
	BaseCallEventContent
	SelectedPartyID string `json:"selected_party_id"`
}

type CallNegotiateEventContent struct {
	BaseCallEventContent
	Lifetime          int                   `json:"lifetime"`
	Description       CallData              `json:"description"`
	SDPStreamMetadata CallSDPStreamMetadata `json:"org.matrix.msc3077.sdp_stream_metadata"`
}

type CallHangupEventContent struct {
	BaseCallEventContent
	Reason CallHangupReason `json:"reason"`
}

type FocusTrackDescription struct {
	StreamID string `json:"stream_id"`
	TrackID  string `json:"track_id"`
	Width    int    `json:"width,omitempty"`
	Height   int    `json:"height,omitempty"`
}

type FocusCallTrackSubscriptionEventContent struct {
	Subscribe   []FocusTrackDescription `json:"subscribe"`
	Unsubscribe []FocusTrackDescription `json:"unsubscribe"`
}

type FocusCallNegotiateEventContent struct {
	Description       CallData              `json:"description"`
	SDPStreamMetadata CallSDPStreamMetadata `json:"sdp_stream_metadata"`
}

type FocusCallSDPStreamMetadataChangedEventContent struct {
	SDPStreamMetadata CallSDPStreamMetadata `json:"sdp_stream_metadata"`
}

type FocusCallPingEventContent struct{}

type FocusCallPongEventContent struct{}
