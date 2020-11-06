// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"errors"
	"strings"
	"sync"
	"time"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"

	"maunium.net/go/mautrix/id"
)

var (
	SessionNotShared = errors.New("session has not been shared")
	SessionExpired   = errors.New("session has expired")
)

// OlmSessionList is a list of OlmSessions. It implements sort.Interface in a way that sorts items
// in reverse alphabetic order, which means the newest session is first.
type OlmSessionList []*OlmSession

func (o OlmSessionList) Len() int {
	return len(o)
}

func (o OlmSessionList) Less(i, j int) bool {
	return strings.Compare(string(o[i].ID()), string(o[j].ID())) > 0
}

func (o OlmSessionList) Swap(i, j int) {
	o[i], o[j] = o[j], o[i]
}

type OlmSession struct {
	Internal olm.Session
	ExpirationMixin
	id id.SessionID
	// This is unexported so gob wouldn't insist on trying to marshaling it
	lock sync.Locker
}

func (session *OlmSession) SetLock(lock sync.Locker) {
	session.lock = lock
}

func (session *OlmSession) Lock() {
	session.lock.Lock()
}

func (session *OlmSession) Unlock() {
	session.lock.Unlock()
}

func (session *OlmSession) ID() id.SessionID {
	if session.id == "" {
		session.id = session.Internal.ID()
	}
	return session.id
}

func wrapSession(session *olm.Session) *OlmSession {
	return &OlmSession{
		Internal: *session,
		lock:     &sync.Mutex{},
		ExpirationMixin: ExpirationMixin{
			TimeMixin: TimeMixin{
				CreationTime: time.Now(),
				UseTime:      time.Now(),
			},
		},
	}
}

func (account *OlmAccount) NewInboundSessionFrom(senderKey id.Curve25519, ciphertext string) (*OlmSession, error) {
	session, err := account.Internal.NewInboundSessionFrom(senderKey, ciphertext)
	if err != nil {
		return nil, err
	}
	_ = account.Internal.RemoveOneTimeKeys(session)
	return wrapSession(session), nil
}

func (session *OlmSession) Encrypt(plaintext []byte) (id.OlmMsgType, []byte) {
	session.UseTime = time.Now()
	return session.Internal.Encrypt(plaintext)
}

func (session *OlmSession) Decrypt(ciphertext string, msgType id.OlmMsgType) ([]byte, error) {
	session.UseTime = time.Now()
	return session.Internal.Decrypt(ciphertext, msgType)
}

type InboundGroupSession struct {
	Internal olm.InboundGroupSession

	SigningKey id.Ed25519
	SenderKey  id.Curve25519
	RoomID     id.RoomID

	ForwardingChains []string

	id id.SessionID
}

func NewInboundGroupSession(senderKey id.SenderKey, signingKey id.Ed25519, roomID id.RoomID, sessionKey string) (*InboundGroupSession, error) {
	igs, err := olm.NewInboundGroupSession([]byte(sessionKey))
	if err != nil {
		return nil, err
	}
	return &InboundGroupSession{
		Internal:         *igs,
		SigningKey:       signingKey,
		SenderKey:        senderKey,
		RoomID:           roomID,
		ForwardingChains: nil,
	}, nil
}

func (igs *InboundGroupSession) ID() id.SessionID {
	if igs.id == "" {
		igs.id = igs.Internal.ID()
	}
	return igs.id
}

type OGSState int

const (
	OGSNotShared OGSState = iota
	OGSAlreadyShared
	OGSIgnored
)

type UserDevice struct {
	UserID   id.UserID
	DeviceID id.DeviceID
}

type OutboundGroupSession struct {
	Internal olm.OutboundGroupSession

	ExpirationMixin
	MaxMessages  int
	MessageCount int

	Users  map[UserDevice]OGSState
	RoomID id.RoomID
	Shared bool

	id      id.SessionID
	content *event.RoomKeyEventContent
}

func NewOutboundGroupSession(roomID id.RoomID, encryptionContent *event.EncryptionEventContent) *OutboundGroupSession {
	ogs := &OutboundGroupSession{
		Internal: *olm.NewOutboundGroupSession(),
		ExpirationMixin: ExpirationMixin{
			TimeMixin: TimeMixin{
				CreationTime: time.Now(),
				UseTime:      time.Now(),
			},
			MaxAge: 7 * 24 * time.Hour,
		},
		MaxMessages: 100,
		Shared:      false,
		Users:       make(map[UserDevice]OGSState),
		RoomID:      roomID,
	}
	if encryptionContent != nil {
		if encryptionContent.RotationPeriodMillis != 0 {
			ogs.MaxAge = time.Duration(encryptionContent.RotationPeriodMillis) * time.Millisecond
		}
		if encryptionContent.RotationPeriodMessages != 0 {
			ogs.MaxMessages = encryptionContent.RotationPeriodMessages
		}
	}
	return ogs
}

func (ogs *OutboundGroupSession) ShareContent() event.Content {
	if ogs.content == nil {
		ogs.content = &event.RoomKeyEventContent{
			Algorithm:  id.AlgorithmMegolmV1,
			RoomID:     ogs.RoomID,
			SessionID:  ogs.ID(),
			SessionKey: ogs.Internal.Key(),
		}
	}
	return event.Content{Parsed: ogs.content}
}

func (ogs *OutboundGroupSession) ID() id.SessionID {
	if ogs.id == "" {
		ogs.id = ogs.Internal.ID()
	}
	return ogs.id
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
	ogs.MessageCount++
	return ogs.Internal.Encrypt(plaintext), nil
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
	if exp.MaxAge == 0 {
		return false
	}
	return exp.CreationTime.Add(exp.MaxAge).Before(time.Now())
}
