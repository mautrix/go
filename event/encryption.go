// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/base64"
	"errors"

	"maunium.net/go/mautrix/id"
)

// Algorithm is a Matrix message encryption algorithm.
// https://matrix.org/docs/spec/client_server/r0.6.0#messaging-algorithm-names
type Algorithm string

const (
	AlgorithmOlmV1    Algorithm = "m.olm.v1.curve25519-aes-sha2"
	AlgorithmMegolmV1 Algorithm = "m.megolm.v1.aes-sha2"
)

var unpaddedBase64 = base64.StdEncoding.WithPadding(base64.NoPadding)

// UnpaddedBase64 is a byte array that implements the JSON Marshaler and Unmarshaler interfaces
// to encode and decode the byte array as unpadded base64.
type UnpaddedBase64 []byte

func (ub64 *UnpaddedBase64) UnmarshalJSON(data []byte) error {
	if data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("failed to decode data into bytes: input doesn't look like a JSON string")
	}
	*ub64 = make([]byte, unpaddedBase64.DecodedLen(len(data)-2))
	_, err := unpaddedBase64.Decode(*ub64, data[1:len(data)-1])
	return err
}

func (ub64 *UnpaddedBase64) MarshalJSON() ([]byte, error) {
	data := make([]byte, unpaddedBase64.EncodedLen(len(*ub64))+2)
	data[0] = '"'
	data[len(data)-1] = '"'
	unpaddedBase64.Encode(data[1:len(data)-1], *ub64)
	return data, nil
}

// EncryptionEventContent represents the content of a m.room.encryption state event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-encryption
type EncryptionEventContent struct {
	// The encryption algorithm to be used to encrypt messages sent in this room. Must be 'm.megolm.v1.aes-sha2'.
	Algorithm Algorithm `json:"algorithm"`
	// How long the session should be used before changing it. 604800000 (a week) is the recommended default.
	RotationPeriodMillis int64 `json:"rotation_period_ms,omitempty"`
	// How many messages should be sent before changing the session. 100 is the recommended default.
	RotationPeriodMessages int `json:"rotation_period_messages,omitempty"`
}

// EncryptedEventContent represents the content of a m.room.encrypted message event.
// This struct only supports the m.megolm.v1.aes-sha2 algorithm. The legacy m.olm.v1 algorithm is not supported.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-encrypted
type EncryptedEventContent struct {
	Algorithm  Algorithm      `json:"algorithm"`
	SenderKey  string         `json:"sender_key"`
	DeviceID   id.DeviceID    `json:"device_id"`
	SessionID  string         `json:"session_id"`
	Ciphertext UnpaddedBase64 `json:"ciphertext"`
}

// RoomKeyEventContent represents the content of a m.room_key to_device event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-key
type RoomKeyEventContent struct {
	Algorithm  Algorithm `json:"algorithm"`
	RoomID     id.RoomID `json:"room_id"`
	SessionID  string    `json:"session_id"`
	SessionKey string    `json:"session_key"`
}

// ForwardedRoomKeyEventContent represents the content of a m.forwarded_room_key to_device event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-forwarded-room-key
type ForwardedRoomKeyEventContent struct {
	RoomKeyEventContent
	SenderClaimedKey   string   `json:"sender_claimed_ed25519_key"`
	ForwardingKeyChain []string `json:"forwarding_curve25519_key_chain"`
}

type KeyRequestAction string

const (
	KeyRequestActionRequest = "request"
	KeyRequestActionCancel  = "request_cancellation"
)

// RoomKeyRequestEventContent represents the content of a m.room_key_request to_device event.
// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-key-request
type RoomKeyRequestEventContent struct {
	Body               RequestedKeyInfo `json:"body"`
	Action             KeyRequestAction `json:"action"`
	RequestingDeviceID id.DeviceID      `json:"requesting_device_id"`
	RequestID          string           `json:"request_id"`
}

type RequestedKeyInfo struct {
	Algorithm Algorithm `json:"algorithm"`
	RoomID    id.RoomID `json:"room_id"`
	SenderKey string    `json:"sender_key"`
	SessionID string    `json:"session_id"`
}
