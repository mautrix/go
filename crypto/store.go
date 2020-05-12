// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/gob"
	"os"
	"sort"
	"sync"

	"maunium.net/go/mautrix/id"
)

type TrustState int

const (
	TrustStateUnset TrustState = iota
	TrustStateVerified
	TrustStateBlacklisted
	TrustStateIgnored
)

type DeviceIdentity struct {
	UserID      id.UserID
	DeviceID    id.DeviceID
	IdentityKey id.Curve25519
	SigningKey  id.Ed25519

	Trust   TrustState
	Deleted bool
	Name    string
}

type Store interface {
	Flush() error

	PutAccount(*OlmAccount) error
	GetAccount() (*OlmAccount, error)

	HasSession(id.SenderKey) bool
	GetSessions(id.SenderKey) (OlmSessionList, error)
	GetLatestSession(id.SenderKey) (*OlmSession, error)
	AddSession(id.SenderKey, *OlmSession) error
	UpdateSession(id.SenderKey, *OlmSession) error

	PutGroupSession(id.RoomID, id.SenderKey, id.SessionID, *InboundGroupSession) error
	GetGroupSession(id.RoomID, id.SenderKey, id.SessionID) (*InboundGroupSession, error)

	PutOutboundGroupSession(id.RoomID, *OutboundGroupSession) error
	GetOutboundGroupSession(id.RoomID) (*OutboundGroupSession, error)
	PopOutboundGroupSession(id.RoomID) error

	ValidateMessageIndex(senderKey id.SenderKey, sessionID id.SessionID, eventID id.EventID, index uint, timestamp int64) bool

	GetDevices(id.UserID) (map[id.DeviceID]*DeviceIdentity, error)
	PutDevices(id.UserID, map[id.DeviceID]*DeviceIdentity) error
	FilterTrackedUsers([]id.UserID) []id.UserID
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
	lock sync.RWMutex
	path string

	Account          *OlmAccount
	Sessions         map[id.SenderKey]OlmSessionList
	GroupSessions    map[id.RoomID]map[id.SenderKey]map[id.SessionID]*InboundGroupSession
	OutGroupSessions map[id.RoomID]*OutboundGroupSession
	MessageIndices   map[messageIndexKey]messageIndexValue
	Devices          map[id.UserID]map[id.DeviceID]*DeviceIdentity
}

var _ Store = (*GobStore)(nil)

func NewGobStore(path string) (*GobStore, error) {
	gs := &GobStore{
		path:             path,
		Sessions:         make(map[id.SenderKey]OlmSessionList),
		GroupSessions:    make(map[id.RoomID]map[id.SenderKey]map[id.SessionID]*InboundGroupSession),
		OutGroupSessions: make(map[id.RoomID]*OutboundGroupSession),
		MessageIndices:   make(map[messageIndexKey]messageIndexValue),
		Devices:          make(map[id.UserID]map[id.DeviceID]*DeviceIdentity),
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

func (gs *GobStore) Flush() error {
	gs.lock.Lock()
	err := gs.save()
	gs.lock.Unlock()
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

func (gs *GobStore) GetSessions(senderKey id.SenderKey) (OlmSessionList, error) {
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
	sort.Sort(gs.Sessions[senderKey])
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *GobStore) UpdateSession(key id.SenderKey, session *OlmSession) error {
	// we don't need to do anything here because the session is a pointer and already stored in our map
	return gs.save()
}

func (gs *GobStore) HasSession(senderKey id.SenderKey) bool {
	gs.lock.RLock()
	sessions, ok := gs.Sessions[senderKey]
	gs.lock.RUnlock()
	return ok && len(sessions) > 0 && !sessions[0].Expired()
}

func (gs *GobStore) GetLatestSession(senderKey id.SenderKey) (*OlmSession, error) {
	gs.lock.RLock()
	sessions, ok := gs.Sessions[senderKey]
	gs.lock.RUnlock()
	if !ok || len(sessions) == 0 {
		return nil, nil
	}
	return sessions[0], nil
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

func (gs *GobStore) PutOutboundGroupSession(roomID id.RoomID, session *OutboundGroupSession) error {
	gs.lock.Lock()
	gs.OutGroupSessions[roomID] = session
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *GobStore) GetOutboundGroupSession(roomID id.RoomID) (*OutboundGroupSession, error) {
	gs.lock.RLock()
	session, ok := gs.OutGroupSessions[roomID]
	gs.lock.RUnlock()
	if !ok {
		return nil, nil
	}
	return session, nil
}

func (gs *GobStore) PopOutboundGroupSession(roomID id.RoomID) error {
	gs.lock.Lock()
	session, ok := gs.OutGroupSessions[roomID]
	if !ok || session == nil || !session.Shared {
		gs.lock.Unlock()
		return nil
	}
	delete(gs.OutGroupSessions, roomID)
	gs.lock.Unlock()
	return nil
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

func (gs *GobStore) GetDevices(userID id.UserID) (map[id.DeviceID]*DeviceIdentity, error) {
	gs.lock.RLock()
	devices, ok := gs.Devices[userID]
	if !ok {
		devices = nil
	}
	gs.lock.RUnlock()
	return devices, nil
}

func (gs *GobStore) PutDevices(userID id.UserID, devices map[id.DeviceID]*DeviceIdentity) error {
	gs.lock.Lock()
	gs.Devices[userID] = devices
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *GobStore) FilterTrackedUsers(users []id.UserID) []id.UserID {
	gs.lock.RLock()
	var ptr int
	for _, userID := range users {
		_, ok := gs.Devices[userID]
		if ok {
			users[ptr] = userID
			ptr++
		}
	}
	gs.lock.RUnlock()
	return users[:ptr]
}
