// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/libolm"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	SessionNotShared = errors.New("session has not been shared")
	SessionExpired   = errors.New("session has expired")
)

// OlmSessionList is a list of OlmSessions.
// It implements sort.Interface so that the session with recent successful decryptions comes first.
type OlmSessionList []*OlmSession

func (o OlmSessionList) Len() int {
	return len(o)
}

func (o OlmSessionList) Less(i, j int) bool {
	return o[i].LastDecryptedTime.After(o[j].LastEncryptedTime)
}

func (o OlmSessionList) Swap(i, j int) {
	o[i], o[j] = o[j], o[i]
}

type OlmSession struct {
	Internal olm.Session
	ExpirationMixin
	id id.SessionID
}

func (session *OlmSession) ID() id.SessionID {
	if session.id == "" {
		session.id = session.Internal.ID()
	}
	return session.id
}

func (session *OlmSession) Describe() string {
	return session.Internal.Describe()
}

func wrapSession(session olm.Session) *OlmSession {
	return &OlmSession{
		Internal: session,
		ExpirationMixin: ExpirationMixin{
			TimeMixin: TimeMixin{
				CreationTime:      time.Now(),
				LastEncryptedTime: time.Now(),
				LastDecryptedTime: time.Now(),
			},
		},
	}
}

func (account *OlmAccount) NewInboundSessionFrom(senderKey id.Curve25519, ciphertext string) (*OlmSession, error) {
	session, err := account.InternalLibolm.NewInboundSessionFrom(&senderKey, ciphertext)
	if err != nil {
		return nil, err
	}
	goolmSession, err := account.InternalGoolm.NewInboundSessionFrom(&senderKey, ciphertext)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(exerrors.Must(goolmSession.Pickle([]byte("123"))), exerrors.Must(session.Pickle([]byte("123")))) {
		panic("goolm inbound session and libolm inbound session from ciphertext are different")
	}

	_ = account.InternalLibolm.RemoveOneTimeKeys(session)
	_ = account.InternalGoolm.RemoveOneTimeKeys(goolmSession)
	return wrapSession(session), nil
}

func (session *OlmSession) Encrypt(plaintext []byte) (id.OlmMsgType, []byte, error) {
	session.LastEncryptedTime = time.Now()
	return session.Internal.Encrypt(plaintext)
}

func (session *OlmSession) Decrypt(ciphertext string, msgType id.OlmMsgType) ([]byte, error) {
	msg, err := session.Internal.Decrypt(ciphertext, msgType)
	if err == nil {
		session.LastDecryptedTime = time.Now()
	}
	return msg, err
}

type RatchetSafety struct {
	NextIndex     uint   `json:"next_index"`
	MissedIndices []uint `json:"missed_indices,omitempty"`
	LostIndices   []uint `json:"lost_indices,omitempty"`
}

type InboundGroupSession struct {
	InternalLibolm olm.InboundGroupSession
	InternalGoolm  olm.InboundGroupSession

	SigningKey id.Ed25519
	SenderKey  id.Curve25519
	RoomID     id.RoomID

	ForwardingChains []string
	RatchetSafety    RatchetSafety

	ReceivedAt       time.Time
	MaxAge           int64
	MaxMessages      int
	IsScheduled      bool
	KeyBackupVersion id.KeyBackupVersion

	id id.SessionID
}

func NewInboundGroupSession(senderKey id.SenderKey, signingKey id.Ed25519, roomID id.RoomID, sessionKey string, maxAge time.Duration, maxMessages int, isScheduled bool) (*InboundGroupSession, error) {
	igs, err := libolm.NewInboundGroupSession([]byte(sessionKey))
	if err != nil {
		return nil, err
	}
	igsGoolm, err := session.NewMegolmInboundSession([]byte(sessionKey))
	if err != nil {
		return nil, err
	}
	return &InboundGroupSession{
		InternalLibolm:   igs,
		InternalGoolm:    igsGoolm,
		SigningKey:       signingKey,
		SenderKey:        senderKey,
		RoomID:           roomID,
		ForwardingChains: []string{},
		ReceivedAt:       time.Now().UTC(),
		MaxAge:           maxAge.Milliseconds(),
		MaxMessages:      maxMessages,
		IsScheduled:      isScheduled,
	}, nil
}

func (igs *InboundGroupSession) ID() id.SessionID {
	if igs.id == "" {
		igs.id = igs.InternalLibolm.ID()
		if igs.id != igs.InternalGoolm.ID() {
			panic(fmt.Sprintf("id different %s %s", igs.id, igs.InternalGoolm.ID()))
		}
	}
	return igs.id
}

func (igs *InboundGroupSession) RatchetTo(index uint32) error {
	exported, err := igs.InternalLibolm.Export(index)
	if err != nil {
		return err
	}
	exportedGoolm, err := igs.InternalGoolm.Export(index)
	if err != nil {
		panic(err)
	} else if !bytes.Equal(exported, exportedGoolm) {
		panic("bytes not equal")
	}
	igs.InternalLibolm, err = libolm.InboundGroupSessionImport(exported)
	if err != nil {
		return err
	}
	igs.InternalGoolm, err = session.NewMegolmInboundSessionFromExport(exportedGoolm)
	return err
}

func (igs *InboundGroupSession) export() (*ExportedSession, error) {
	key, err := igs.InternalLibolm.Export(igs.InternalLibolm.FirstKnownIndex())
	if err != nil {
		return nil, fmt.Errorf("failed to export session: %w", err)
	}
	keyGoolm := exerrors.Must(igs.InternalGoolm.Export(igs.InternalGoolm.FirstKnownIndex()))
	if !bytes.Equal(key, keyGoolm) {
		panic("keys not equal")
	}
	return &ExportedSession{
		Algorithm:         id.AlgorithmMegolmV1,
		ForwardingChains:  igs.ForwardingChains,
		RoomID:            igs.RoomID,
		SenderKey:         igs.SenderKey,
		SenderClaimedKeys: SenderClaimedKeys{},
		SessionID:         igs.ID(),
		SessionKey:        string(key),
	}, nil
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

func NewOutboundGroupSession(roomID id.RoomID, encryptionContent *event.EncryptionEventContent) (*OutboundGroupSession, error) {
	internal, err := olm.NewOutboundGroupSession()
	if err != nil {
		return nil, err
	}
	ogs := &OutboundGroupSession{
		Internal: internal,
		ExpirationMixin: ExpirationMixin{
			TimeMixin: TimeMixin{
				CreationTime:      time.Now(),
				LastEncryptedTime: time.Now(),
			},
			MaxAge: 7 * 24 * time.Hour,
		},
		MaxMessages: 100,
		Shared:      false,
		Users:       make(map[UserDevice]OGSState),
		RoomID:      roomID,
	}
	if encryptionContent != nil {
		// Clamp rotation period to prevent unreasonable values
		// Similar to https://github.com/matrix-org/matrix-rust-sdk/blob/matrix-sdk-crypto-0.7.1/crates/matrix-sdk-crypto/src/olm/group_sessions/outbound.rs#L415-L441
		if encryptionContent.RotationPeriodMillis != 0 {
			ogs.MaxAge = time.Duration(encryptionContent.RotationPeriodMillis) * time.Millisecond
			ogs.MaxAge = min(max(ogs.MaxAge, 1*time.Hour), 365*24*time.Hour)
		}
		if encryptionContent.RotationPeriodMessages != 0 {
			ogs.MaxMessages = min(max(encryptionContent.RotationPeriodMessages, 1), 10000)
		}
	}
	return ogs, nil
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
	ogs.LastEncryptedTime = time.Now()
	return ogs.Internal.Encrypt(plaintext)
}

type TimeMixin struct {
	CreationTime      time.Time
	LastEncryptedTime time.Time
	LastDecryptedTime time.Time
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
