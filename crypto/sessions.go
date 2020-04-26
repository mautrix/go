// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"time"

	"github.com/pkg/errors"

	"maunium.net/go/mautrix/crypto/olm"

	"maunium.net/go/mautrix/id"
)

var (
	SessionNotShared = errors.New("session has not been shared")
	SessionExpired   = errors.New("session has expired")
)

type UserDevice struct {
	UserID   id.UserID
	DeviceID id.DeviceID
}

type OlmSession struct {
	olm.Session
	ExpirationMixin
}

func wrapSession(session *olm.Session) *OlmSession {
	return &OlmSession{
		Session: *session,
		ExpirationMixin: ExpirationMixin{
			TimeMixin: TimeMixin{
				CreationTime: time.Now(),
				UseTime:      time.Now(),
			},
			MaxAge: 7 * 24 * time.Hour,
		},
	}
}

func (account *OlmAccount) NewInboundSessionFrom(senderKey id.Curve25519, ciphertext string) (*OlmSession, error) {
	session, err := account.Account.NewInboundSessionFrom(senderKey, ciphertext)
	if err != nil {
		return nil, err
	}
	_ = account.RemoveOneTimeKeys(session)
	return wrapSession(session), nil
}

func (session *OlmSession) Encrypt(plaintext string) (id.OlmMsgType, string) {
	session.UseTime = time.Now()
	return session.Session.Encrypt(plaintext)
}

func (session *OlmSession) Decrypt(ciphertext string, msgType id.OlmMsgType) ([]byte, error) {
	session.UseTime = time.Now()
	return session.Session.Decrypt(ciphertext, msgType)
}

type InboundGroupSession struct {
	olm.InboundGroupSession

	SigningKey id.Ed25519
	SenderKey  id.Curve25519
	RoomID     id.RoomID

	ForwardingChains []string
}

func NewInboundGroupSession(senderKey id.SenderKey, signingKey id.Ed25519, roomID id.RoomID, sessionKey string) (*InboundGroupSession, error) {
	igs, err := olm.NewInboundGroupSession([]byte(sessionKey))
	if err != nil {
		return nil, err
	}
	return &InboundGroupSession{
		InboundGroupSession: *igs,
		SigningKey:          signingKey,
		SenderKey:           senderKey,
		RoomID:              roomID,
		ForwardingChains:    nil,
	}, nil
}

type OutboundGroupSession struct {
	olm.OutboundGroupSession

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

func (ogs *OutboundGroupSession) Encrypt(plaintext []byte) ([]byte, error) {
	if !ogs.Shared {
		return nil, SessionNotShared
	} else if ogs.Expired() {
		return nil, SessionExpired
	}
	return ogs.OutboundGroupSession.Encrypt(plaintext), nil
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
