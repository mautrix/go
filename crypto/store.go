// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/gob"
	"os"
	"sync"

	"maunium.net/go/mautrix/id"
)

type Store interface {
	PutAccount(*OlmAccount) error
	GetAccount() (*OlmAccount, error)

	GetSessions(id.SenderKey) ([]*OlmSession, error)
	AddSession(id.SenderKey, *OlmSession) error

	PutGroupSession(id.RoomID, id.SenderKey, id.SessionID, *InboundGroupSession) error
	GetGroupSession(id.RoomID, id.SenderKey, id.SessionID) (*InboundGroupSession, error)

	ValidateMessageIndex(senderKey id.SenderKey, sessionID id.SessionID, eventID id.EventID, index uint, timestamp int64) bool
}

type messageIndexKey struct {
	SenderKey id.SenderKey
	SessionID id.SessionID
	Index     uint
}

type messageIndexValue struct {
	EventID   id.EventID
	Timestamp int64
}

type GobStore struct {
	lock sync.Mutex
	path string

	Account        *OlmAccount
	Sessions       map[id.SenderKey][]*OlmSession
	GroupSessions  map[id.RoomID]map[id.SenderKey]map[id.SessionID]*InboundGroupSession
	MessageIndices map[messageIndexKey]messageIndexValue
}

func NewGobStore(path string) (*GobStore, error) {
	gs := &GobStore{
		path:           path,
		Sessions:       make(map[id.SenderKey][]*OlmSession),
		GroupSessions:  make(map[id.RoomID]map[id.SenderKey]map[id.SessionID]*InboundGroupSession),
		MessageIndices: make(map[messageIndexKey]messageIndexValue),
	}
	return gs, gs.load()
}

func (gs *GobStore) save() error {
	file, err := os.OpenFile(gs.path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = gob.NewEncoder(file).Encode(gs)
	_ = file.Close()
	return err
}

func (gs *GobStore) load() error {
	file, err := os.OpenFile(gs.path, os.O_RDONLY, 0600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	err = gob.NewDecoder(file).Decode(gs)
	_ = file.Close()
	return err
}

func (gs *GobStore) GetAccount() (*OlmAccount, error) {
	return gs.Account, nil
}

func (gs *GobStore) PutAccount(account *OlmAccount) error {
	gs.lock.Lock()
	gs.Account = account
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *GobStore) GetSessions(senderKey id.SenderKey) ([]*OlmSession, error) {
	gs.lock.Lock()
	sessions, ok := gs.Sessions[senderKey]
	if !ok {
		sessions = []*OlmSession{}
		gs.Sessions[senderKey] = sessions
	}
	gs.lock.Unlock()
	return sessions, nil
}

func (gs *GobStore) AddSession(senderKey id.SenderKey, session *OlmSession) error {
	gs.lock.Lock()
	sessions, _ := gs.Sessions[senderKey]
	gs.Sessions[senderKey] = append(sessions, session)
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *GobStore) getGroupSessions(roomID id.RoomID, senderKey id.SenderKey) map[id.SessionID]*InboundGroupSession {
	room, ok := gs.GroupSessions[roomID]
	if !ok {
		room = make(map[id.SenderKey]map[id.SessionID]*InboundGroupSession)
		gs.GroupSessions[roomID] = room
	}
	sender, ok := room[senderKey]
	if !ok {
		sender = make(map[id.SessionID]*InboundGroupSession)
		room[senderKey] = sender
	}
	return sender
}

func (gs *GobStore) PutGroupSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, igs *InboundGroupSession) error {
	gs.lock.Lock()
	gs.getGroupSessions(roomID, senderKey)[sessionID] = igs
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *GobStore) GetGroupSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID) (*InboundGroupSession, error) {
	gs.lock.Lock()
	sessions := gs.getGroupSessions(roomID, senderKey)
	session, ok := sessions[sessionID]
	gs.lock.Unlock()
	if !ok {
		return nil, nil
	}
	return session, nil
}

func (gs *GobStore) ValidateMessageIndex(senderKey id.SenderKey, sessionID id.SessionID, eventID id.EventID, index uint, timestamp int64) bool {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	key := messageIndexKey{
		SenderKey: senderKey,
		SessionID: sessionID,
		Index:     index,
	}
	val, ok := gs.MessageIndices[key]
	if !ok {
		gs.MessageIndices[key] = messageIndexValue{
			EventID:   eventID,
			Timestamp: timestamp,
		}
		_ = gs.save()
		return true
	}
	if val.EventID != eventID || val.Timestamp != timestamp {
		return false
	}
	return true
}
