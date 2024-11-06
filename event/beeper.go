// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"

	"maunium.net/go/mautrix/id"
)

type MessageStatusReason string

const (
	MessageStatusGenericError      MessageStatusReason = "m.event_not_handled"
	MessageStatusUnsupported       MessageStatusReason = "com.beeper.unsupported_event"
	MessageStatusUndecryptable     MessageStatusReason = "com.beeper.undecryptable_event"
	MessageStatusTooOld            MessageStatusReason = "m.event_too_old"
	MessageStatusNetworkError      MessageStatusReason = "m.foreign_network_error"
	MessageStatusNoPermission      MessageStatusReason = "m.no_permission"
	MessageStatusBridgeUnavailable MessageStatusReason = "m.bridge_unavailable"
)

type MessageStatus string

const (
	MessageStatusSuccess   MessageStatus = "SUCCESS"
	MessageStatusPending   MessageStatus = "PENDING"
	MessageStatusRetriable MessageStatus = "FAIL_RETRIABLE"
	MessageStatusFail      MessageStatus = "FAIL_PERMANENT"
)

type BeeperMessageStatusEventContent struct {
	Network   string              `json:"network,omitempty"`
	RelatesTo RelatesTo           `json:"m.relates_to"`
	Status    MessageStatus       `json:"status"`
	Reason    MessageStatusReason `json:"reason,omitempty"`
	// Deprecated: clients were showing this to users even though they aren't supposed to.
	// Use InternalError for error messages that should be included in bug reports, but not shown in the UI.
	Error         string `json:"error,omitempty"`
	InternalError string `json:"internal_error,omitempty"`
	Message       string `json:"message,omitempty"`

	LastRetry id.EventID `json:"last_retry,omitempty"`

	MutateEventKey string `json:"mutate_event_key,omitempty"`

	// Indicates the set of users to whom the event was delivered. If nil, then
	// the client should not expect delivered status at any later point. If not
	// nil (even if empty), this field indicates which users the event was
	// delivered to.
	DeliveredToUsers *[]id.UserID `json:"delivered_to_users,omitempty"`
}

type BeeperRetryMetadata struct {
	OriginalEventID id.EventID `json:"original_event_id"`
	RetryCount      int        `json:"retry_count"`
	// last_retry is also present, but not used by bridges
}

type BeeperRoomKeyAckEventContent struct {
	RoomID            id.RoomID    `json:"room_id"`
	SessionID         id.SessionID `json:"session_id"`
	FirstMessageIndex int          `json:"first_message_index"`
}

type LinkPreview struct {
	CanonicalURL string `json:"og:url,omitempty"`
	Title        string `json:"og:title,omitempty"`
	Type         string `json:"og:type,omitempty"`
	Description  string `json:"og:description,omitempty"`

	ImageURL id.ContentURIString `json:"og:image,omitempty"`

	ImageSize   int    `json:"matrix:image:size,omitempty"`
	ImageWidth  int    `json:"og:image:width,omitempty"`
	ImageHeight int    `json:"og:image:height,omitempty"`
	ImageType   string `json:"og:image:type,omitempty"`
}

// BeeperLinkPreview contains the data for a bundled URL preview as specified in MSC4095
//
// https://github.com/matrix-org/matrix-spec-proposals/pull/4095
type BeeperLinkPreview struct {
	LinkPreview

	MatchedURL      string             `json:"matched_url,omitempty"`
	ImageEncryption *EncryptedFileInfo `json:"beeper:image:encryption,omitempty"`
}

type BeeperProfileExtra struct {
	RemoteID     string   `json:"com.beeper.bridge.remote_id,omitempty"`
	Identifiers  []string `json:"com.beeper.bridge.identifiers,omitempty"`
	Service      string   `json:"com.beeper.bridge.service,omitempty"`
	Network      string   `json:"com.beeper.bridge.network,omitempty"`
	IsBridgeBot  bool     `json:"com.beeper.bridge.is_bridge_bot,omitempty"`
	IsNetworkBot bool     `json:"com.beeper.bridge.is_network_bot,omitempty"`
}

type BeeperPerMessageProfile struct {
	ID          string               `json:"id"`
	Displayname string               `json:"displayname,omitempty"`
	AvatarURL   *id.ContentURIString `json:"avatar_url,omitempty"`
	AvatarFile  *EncryptedFileInfo   `json:"avatar_file,omitempty"`
}

type BeeperEncodedOrder struct {
	order    int64
	suborder int64
}

func NewBeeperEncodedOrder(order int64, suborder int64) BeeperEncodedOrder {
	return BeeperEncodedOrder{order: order, suborder: suborder}
}

func BeeperEncodedOrderFromString(str string) (BeeperEncodedOrder, error) {
	order, suborder, err := decodeIntPair(str)
	if err != nil {
		return BeeperEncodedOrder{}, err
	}
	return BeeperEncodedOrder{order: order, suborder: suborder}, nil
}

func (b BeeperEncodedOrder) String() string {
	return encodeIntPair(b.order, b.suborder)
}

func (b BeeperEncodedOrder) OrderPair() (int64, int64) {
	return b.order, b.suborder
}

func (b BeeperEncodedOrder) IsZero() bool {
	return b.order == 0 && b.suborder == 0
}

func (b BeeperEncodedOrder) MarshalJSON() ([]byte, error) {
	return []byte(`"` + b.String() + `"`), nil
}

func (b *BeeperEncodedOrder) UnmarshalJSON(data []byte) error {
	str := string(data)
	if len(str) < 2 {
		return fmt.Errorf("invalid encoded order string: %s", str)
	}
	decoded, err := BeeperEncodedOrderFromString(str[1 : len(str)-1])
	if err != nil {
		return err
	}
	b.order, b.suborder = decoded.order, decoded.suborder
	return nil
}

// encodeIntPair encodes two int64 integers into a lexicographically sortable string
func encodeIntPair(a, b int64) string {
	// Create a buffer to hold the binary representation of the integers.
	var buf [16]byte

	// Flip the sign bit of each integer to map the entire int64 range to uint64
	// in a way that preserves the order of the original integers.
	//
	// Explanation:
	// - By XORing with (1 << 63), we flip the most significant bit (sign bit) of the int64 value.
	// - Negative numbers (which have a sign bit of 1) become smaller uint64 values.
	// - Non-negative numbers (with a sign bit of 0) become larger uint64 values.
	// - This mapping preserves the original ordering when the uint64 values are compared.
	binary.BigEndian.PutUint64(buf[0:8], uint64(a)^(1<<63))
	binary.BigEndian.PutUint64(buf[8:16], uint64(b)^(1<<63))

	// Encode the buffer into a Base32 string without padding using the Hex encoding.
	//
	// Explanation:
	// - Base32 encoding converts binary data into a text representation using 32 ASCII characters.
	// - Using Base32HexEncoding ensures that the characters are in lexicographical order.
	// - Disabling padding results in a consistent string length, which is important for sorting.
	encoded := base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(buf[:])

	return encoded
}

// decodeIntPair decodes a string produced by encodeIntPair back into the original int64 integers
func decodeIntPair(encoded string) (int64, int64, error) {
	// Decode the Base32 string back into the original byte buffer.
	buf, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to decode string: %w", err)
	}

	// Check that the decoded buffer has the expected length.
	if len(buf) != 16 {
		return 0, 0, fmt.Errorf("invalid encoded string length: expected 16 bytes, got %d", len(buf))
	}

	// Read the uint64 values from the buffer using big-endian byte order.
	aPos := binary.BigEndian.Uint64(buf[0:8])
	bPos := binary.BigEndian.Uint64(buf[8:16])

	// Reverse the sign bit flip to retrieve the original int64 values.
	a := int64(aPos ^ (1 << 63))
	b := int64(bPos ^ (1 << 63))

	return a, b, nil
}
