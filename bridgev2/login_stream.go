// Copyright (c) 2026 Beeper
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

const LoginClientStreamMaxChunkSize = 64 * 1024

// LoginClientStreamPacket carries raw upgraded-connection bytes, not WebSocket messages.
// Sequence zero is reserved for empty poll responses. Both directions start at one.
type LoginClientStreamPacket struct {
	Sequence uint64 `json:"sequence"`
	Data     []byte `json:"data,omitempty"`
	Closed   bool   `json:"closed,omitempty"`
	Error    string `json:"error,omitempty"`
}

type LoginClientStreamExchange struct {
	Ack    uint64                   `json:"ack,omitempty"`
	Packet *LoginClientStreamPacket `json:"packet,omitempty"`
}

type LoginClientStreamExchangeResponse struct {
	Ack uint64 `json:"ack"`
}
