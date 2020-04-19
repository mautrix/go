// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"errors"
	"time"

	"maunium.net/go/mautrix/id"
	"maunium.net/go/olm"
)

var (
	SessionNotShared = errors.New("session has not been shared")
	SessionExpired   = errors.New("session has expired")
)

type UserDevice struct {
	UserID   id.UserID
	DeviceID id.DeviceID
}

type OlmAccount struct {
	*olm.Account
	Shared bool
}

type OlmSession struct {
	*olm.Session
	ExpirationMixin
}

func (session *OlmSession) Encrypt(plaintext string) (olm.MsgType, string) {
	session.UseTime = time.Now()
	return session.Session.Encrypt(plaintext)
}

func (session *OlmSession) Decrypt(ciphertext string, msgType olm.MsgType) (string, error) {
	session.UseTime = time.Now()
	return session.Session.Decrypt(ciphertext, msgType)
}

type TimeMixin struct {
	CreationTime time.Time
	UseTime      time.Time
}

type ExpirationMixin struct {
	TimeMixin
	MaxAge time.Duration
}

func (exp *ExpirationMixin) Expired() bool {
	return exp.CreationTime.Add(exp.MaxAge).Before(time.Now())
}

type InboundGroupSession struct {
	*olm.InboundGroupSession

	SigningKey string
	SenderKey  string
	RoomID     id.RoomID

	ForwardingChains []string
}

type OutboundGroupSession struct {
	*olm.OutboundGroupSession

	ExpirationMixin
	MaxMessages  int
	MessageCount int

	UsersSharedWith []UserDevice
	UsersIgnored    []UserDevice
	Shared          bool
}

func (ogs *OutboundGroupSession) Expired() bool {
	return ogs.MessageCount >= ogs.MaxMessages || ogs.ExpirationMixin.Expired()
}

func (ogs *OutboundGroupSession) Encrypt(plaintext string) (string, error) {
	if !ogs.Shared {
		return "", SessionNotShared
	} else if ogs.Expired() {
		return "", SessionExpired
	}
	return ogs.OutboundGroupSession.Encrypt(plaintext), nil
}
