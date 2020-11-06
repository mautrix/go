// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// TrustState determines how trusted a device is.
type TrustState int

const (
	TrustStateUnset TrustState = iota
	TrustStateVerified
	TrustStateBlacklisted
	TrustStateIgnored
)

func (ts TrustState) String() string {
	switch ts {
	case TrustStateUnset:
		return "unverified"
	case TrustStateVerified:
		return "verified"
	case TrustStateBlacklisted:
		return "blacklisted"
	case TrustStateIgnored:
		return "ignored"
	default:
		return ""
	}
}

// DeviceIdentity contains the identity details of a device and some additional info.
type DeviceIdentity struct {
	UserID      id.UserID
	DeviceID    id.DeviceID
	IdentityKey id.Curve25519
	SigningKey  id.Ed25519

	Trust   TrustState
	Deleted bool
	Name    string
}

func (device *DeviceIdentity) Fingerprint() string {
	return Fingerprint(device.SigningKey)
}

var ErrGroupSessionWithheld = errors.New("group session has been withheld")

// Store is used by OlmMachine to store Olm and Megolm sessions, user device lists and message indices.
//
// General implementation details:
// * Get methods should not return errors if the requested data does not exist in the store, they should simply return nil.
// * Update methods may assume that the pointer is the same as what has earlier been added to or fetched from the store.
// * OlmSessions should be cached so that the mutex works. Alternatively, implementations can use OlmSession.SetLock to provide a custom mutex implementation.
type Store interface {
	// Flush ensures that everything in the store is persisted to disk.
	// This doesn't have to do anything, e.g. for database-backed implementations that persist everything immediately.
	Flush() error

	// PutAccount updates the OlmAccount in the store.
	PutAccount(*OlmAccount) error
	// GetAccount returns the OlmAccount in the store that was previously inserted with PutAccount.
	GetAccount() (*OlmAccount, error)

	// AddSession inserts an Olm session into the store.
	AddSession(id.SenderKey, *OlmSession) error
	// HasSession returns whether or not the store has an Olm session with the given sender key.
	HasSession(id.SenderKey) bool
	// GetSessions returns all Olm sessions in the store with the given sender key.
	GetSessions(id.SenderKey) (OlmSessionList, error)
	// GetLatestSession returns the session with the highest session ID (lexiographically sorting).
	// It's usually safe to return the most recently added session if sorting by session ID is too difficult.
	GetLatestSession(id.SenderKey) (*OlmSession, error)
	// UpdateSession updates a session that has previously been inserted with AddSession.
	UpdateSession(id.SenderKey, *OlmSession) error

	// PutGroupSession inserts an inbound Megolm session into the store. If an earlier withhold event has been inserted
	// with PutWithheldGroupSession, this call should replace that. However, PutWithheldGroupSession must not replace
	// sessions inserted with this call.
	PutGroupSession(id.RoomID, id.SenderKey, id.SessionID, *InboundGroupSession) error
	// GetGroupSession gets an inbound Megolm session from the store. If the group session has been withheld
	// (i.e. a room key withheld event has been saved with PutWithheldGroupSession), this should return the
	// ErrGroupSessionWithheld error. The caller may use GetWithheldGroupSession to find more details.
	GetGroupSession(id.RoomID, id.SenderKey, id.SessionID) (*InboundGroupSession, error)
	// PutWithheldGroupSession tells the store that a specific Megolm session was withheld.
	PutWithheldGroupSession(event.RoomKeyWithheldEventContent) error
	// GetWithheldGroupSession gets the event content that was previously inserted with PutWithheldGroupSession.
	GetWithheldGroupSession(id.RoomID, id.SenderKey, id.SessionID) (*event.RoomKeyWithheldEventContent, error)

	// GetGroupSessionsForRoom gets all the inbound Megolm sessions for a specific room. This is used for creating key
	// export files. Unlike GetGroupSession, this should not return any errors about withheld keys.
	GetGroupSessionsForRoom(id.RoomID) ([]*InboundGroupSession, error)
	// GetGroupSessionsForRoom gets all the inbound Megolm sessions in the store. This is used for creating key export
	// files. Unlike GetGroupSession, this should not return any errors about withheld keys.
	GetAllGroupSessions() ([]*InboundGroupSession, error)

	// AddOutboundGroupSession inserts the given outbound Megolm session into the store.
	//
	// The store should index inserted sessions by the RoomID field to support getting and removing sessions.
	// There will only be one outbound session per room ID at a time.
	AddOutboundGroupSession(*OutboundGroupSession) error
	// UpdateOutboundGroupSession updates the given outbound Megolm session in the store.
	UpdateOutboundGroupSession(*OutboundGroupSession) error
	// GetOutboundGroupSession gets the stored outbound Megolm session for the given room ID from the store.
	GetOutboundGroupSession(id.RoomID) (*OutboundGroupSession, error)
	// RemoveOutboundGroupSession removes the stored outbound Megolm session for the given room ID.
	RemoveOutboundGroupSession(id.RoomID) error

	// ValidateMessageIndex validates that the given message details aren't from a replay attack.
	//
	// Implementations should store a map from (senderKey, sessionID, index) to (eventID, timestamp), then use that map
	// to check whether or not the message index is valid:
	//
	// * If the map key doesn't exist, the given values should be stored and this should return true.
	// * If the map key exists and the stored values match the given values, this should return true.
	// * If the map key exists, but the stored values do not match the given values, this should return false.
	ValidateMessageIndex(senderKey id.SenderKey, sessionID id.SessionID, eventID id.EventID, index uint, timestamp int64) bool

	// GetDevices returns a map from device ID to DeviceIdentity containing all devices of a given user.
	GetDevices(id.UserID) (map[id.DeviceID]*DeviceIdentity, error)
	// GetDevice returns a specific device of a given user.
	GetDevice(id.UserID, id.DeviceID) (*DeviceIdentity, error)
	// PutDevice stores a single device for a user, replacing it if it exists already.
	PutDevice(id.UserID, *DeviceIdentity) error
	// PutDevices overrides the stored device list for the given user with the given list.
	PutDevices(id.UserID, map[id.DeviceID]*DeviceIdentity) error
	// FilterTrackedUsers returns a filtered version of the given list that only includes user IDs whose device lists
	// have been stored with PutDevices. A user is considered tracked even if the PutDevices list was empty.
	FilterTrackedUsers([]id.UserID) []id.UserID

	// PutCrossSigningKey stores a cross-signing key of some user along with its usage.
	PutCrossSigningKey(id.UserID, id.CrossSigningUsage, id.Ed25519) error
	// GetCrossSigningKeys retrieves a user's stored cross-signing keys.
	GetCrossSigningKeys(id.UserID) (map[id.CrossSigningUsage]id.Ed25519, error)
	// PutSignature stores a signature of a cross-signing or device key along with the signer's user ID and key.
	PutSignature(id.UserID, id.Ed25519, id.UserID, id.Ed25519, string) error
	// GetSignaturesForKeyBy returns the signatures for a cross-signing or device key by the given signer.
	GetSignaturesForKeyBy(id.UserID, id.Ed25519, id.UserID) (map[id.Ed25519]string, error)
	// IsKeySignedBy returns whether a cross-signing or device key is signed by the given signer.
	IsKeySignedBy(id.UserID, id.Ed25519, id.UserID, id.Ed25519) (bool, error)
	// DropSignaturesByKey deletes the signatures made by the given user and key from the store. It returns the number of signatures deleted.
	DropSignaturesByKey(id.UserID, id.Ed25519) (int64, error)
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

// GobStore is a simple Store implementation that dumps everything into a .gob file.
type GobStore struct {
	lock sync.RWMutex
	path string

	Account               *OlmAccount
	Sessions              map[id.SenderKey]OlmSessionList
	GroupSessions         map[id.RoomID]map[id.SenderKey]map[id.SessionID]*InboundGroupSession
	WithheldGroupSessions map[id.RoomID]map[id.SenderKey]map[id.SessionID]*event.RoomKeyWithheldEventContent
	OutGroupSessions      map[id.RoomID]*OutboundGroupSession
	MessageIndices        map[messageIndexKey]messageIndexValue
	Devices               map[id.UserID]map[id.DeviceID]*DeviceIdentity
	CrossSigningKeys      map[id.UserID]map[id.CrossSigningUsage]id.Ed25519
	KeySignatures         map[id.UserID]map[id.Ed25519]map[id.UserID]map[id.Ed25519]string
}

var _ Store = (*GobStore)(nil)

// NewGobStore creates a new GobStore that saves everything to the given file.
func NewGobStore(path string) (*GobStore, error) {
	gs := &GobStore{
		path:                  path,
		Sessions:              make(map[id.SenderKey]OlmSessionList),
		GroupSessions:         make(map[id.RoomID]map[id.SenderKey]map[id.SessionID]*InboundGroupSession),
		WithheldGroupSessions: make(map[id.RoomID]map[id.SenderKey]map[id.SessionID]*event.RoomKeyWithheldEventContent),
		OutGroupSessions:      make(map[id.RoomID]*OutboundGroupSession),
		MessageIndices:        make(map[messageIndexKey]messageIndexValue),
		Devices:               make(map[id.UserID]map[id.DeviceID]*DeviceIdentity),
		CrossSigningKeys:      make(map[id.UserID]map[id.CrossSigningUsage]id.Ed25519),
		KeySignatures:         make(map[id.UserID]map[id.Ed25519]map[id.UserID]map[id.Ed25519]string),
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

func (gs *GobStore) UpdateSession(_ id.SenderKey, _ *OlmSession) error {
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
	session, ok := gs.getGroupSessions(roomID, senderKey)[sessionID]
	if !ok {
		withheld, ok := gs.getWithheldGroupSessions(roomID, senderKey)[sessionID]
		gs.lock.Unlock()
		if ok {
			return nil, fmt.Errorf("%w (%s)", ErrGroupSessionWithheld, withheld.Code)
		}
		return nil, nil
	}
	gs.lock.Unlock()
	return session, nil
}

func (gs *GobStore) getWithheldGroupSessions(roomID id.RoomID, senderKey id.SenderKey) map[id.SessionID]*event.RoomKeyWithheldEventContent {
	room, ok := gs.WithheldGroupSessions[roomID]
	if !ok {
		room = make(map[id.SenderKey]map[id.SessionID]*event.RoomKeyWithheldEventContent)
		gs.WithheldGroupSessions[roomID] = room
	}
	sender, ok := room[senderKey]
	if !ok {
		sender = make(map[id.SessionID]*event.RoomKeyWithheldEventContent)
		room[senderKey] = sender
	}
	return sender
}

func (gs *GobStore) PutWithheldGroupSession(content event.RoomKeyWithheldEventContent) error {
	gs.lock.Lock()
	gs.getWithheldGroupSessions(content.RoomID, content.SenderKey)[content.SessionID] = &content
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *GobStore) GetWithheldGroupSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID) (*event.RoomKeyWithheldEventContent, error) {
	gs.lock.Lock()
	session, ok := gs.getWithheldGroupSessions(roomID, senderKey)[sessionID]
	gs.lock.Unlock()
	if !ok {
		return nil, nil
	}
	return session, nil
}

func (gs *GobStore) GetGroupSessionsForRoom(roomID id.RoomID) ([]*InboundGroupSession, error) {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	room, ok := gs.GroupSessions[roomID]
	if !ok {
		return []*InboundGroupSession{}, nil
	}
	var result []*InboundGroupSession
	for _, sessions := range room {
		for _, session := range sessions {
			result = append(result, session)
		}
	}
	return result, nil
}

func (gs *GobStore) GetAllGroupSessions() ([]*InboundGroupSession, error) {
	gs.lock.Lock()
	var result []*InboundGroupSession
	for _, room := range gs.GroupSessions {
		for _, sessions := range room {
			for _, session := range sessions {
				result = append(result, session)
			}
		}
	}
	gs.lock.Unlock()
	return result, nil
}

func (gs *GobStore) AddOutboundGroupSession(session *OutboundGroupSession) error {
	gs.lock.Lock()
	gs.OutGroupSessions[session.RoomID] = session
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *GobStore) UpdateOutboundGroupSession(_ *OutboundGroupSession) error {
	// we don't need to do anything here because the session is a pointer and already stored in our map
	return gs.save()
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

func (gs *GobStore) RemoveOutboundGroupSession(roomID id.RoomID) error {
	gs.lock.Lock()
	session, ok := gs.OutGroupSessions[roomID]
	if !ok || session == nil {
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

func (gs *GobStore) GetDevice(userID id.UserID, deviceID id.DeviceID) (*DeviceIdentity, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	devices, ok := gs.Devices[userID]
	if !ok {
		return nil, nil
	}
	device, ok := devices[deviceID]
	if !ok {
		return nil, nil
	}
	return device, nil
}

func (gs *GobStore) PutDevice(userID id.UserID, device *DeviceIdentity) error {
	gs.lock.Lock()
	devices, ok := gs.Devices[userID]
	if !ok {
		devices = make(map[id.DeviceID]*DeviceIdentity)
		gs.Devices[userID] = devices
	}
	devices[device.DeviceID] = device
	err := gs.save()
	gs.lock.Unlock()
	return err
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

func (gs *GobStore) PutCrossSigningKey(userID id.UserID, usage id.CrossSigningUsage, key id.Ed25519) error {
	gs.lock.RLock()
	userKeys, ok := gs.CrossSigningKeys[userID]
	if !ok {
		userKeys = make(map[id.CrossSigningUsage]id.Ed25519)
		gs.CrossSigningKeys[userID] = userKeys
	}
	userKeys[usage] = key
	err := gs.save()
	gs.lock.RUnlock()
	return err
}

func (gs *GobStore) GetCrossSigningKeys(userID id.UserID) (map[id.CrossSigningUsage]id.Ed25519, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	keys, ok := gs.CrossSigningKeys[userID]
	if !ok {
		return map[id.CrossSigningUsage]id.Ed25519{}, nil
	}
	return keys, nil
}

func (gs *GobStore) PutSignature(signedUserID id.UserID, signedKey id.Ed25519, signerUserID id.UserID, signerKey id.Ed25519, signature string) error {
	gs.lock.RLock()
	signedUserSigs, ok := gs.KeySignatures[signedUserID]
	if !ok {
		signedUserSigs = make(map[id.Ed25519]map[id.UserID]map[id.Ed25519]string)
		gs.KeySignatures[signedUserID] = signedUserSigs
	}
	signaturesForKey, ok := signedUserSigs[signedKey]
	if !ok {
		signaturesForKey = make(map[id.UserID]map[id.Ed25519]string)
		signedUserSigs[signedKey] = signaturesForKey
	}
	signedByUser, ok := signaturesForKey[signerUserID]
	if !ok {
		signedByUser = make(map[id.Ed25519]string)
		signaturesForKey[signerUserID] = signedByUser
	}
	signedByUser[signerKey] = signature
	err := gs.save()
	gs.lock.RUnlock()
	return err
}

func (gs *GobStore) GetSignaturesForKeyBy(userID id.UserID, key id.Ed25519, signerID id.UserID) (map[id.Ed25519]string, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	userKeys, ok := gs.KeySignatures[userID]
	if !ok {
		return map[id.Ed25519]string{}, nil
	}
	sigsForKey, ok := userKeys[key]
	if !ok {
		return map[id.Ed25519]string{}, nil
	}
	sigsBySigner, ok := sigsForKey[signerID]
	if !ok {
		return map[id.Ed25519]string{}, nil
	}
	return sigsBySigner, nil
}

func (gs *GobStore) IsKeySignedBy(userID id.UserID, key id.Ed25519, signerID id.UserID, signerKey id.Ed25519) (bool, error) {
	sigs, err := gs.GetSignaturesForKeyBy(userID, key, signerID)
	if err != nil {
		return false, err
	}
	_, ok := sigs[signerKey]
	return ok, nil
}

func (gs *GobStore) DropSignaturesByKey(userID id.UserID, key id.Ed25519) (int64, error) {
	var count int64
	gs.lock.RLock()
	for _, userSigs := range gs.KeySignatures {
		for _, keySigs := range userSigs {
			if signedBySigner, ok := keySigs[userID]; ok {
				if _, ok := signedBySigner[key]; ok {
					count++
					delete(signedBySigner, key)
				}
			}
		}
	}
	gs.lock.RUnlock()
	return count, nil
}
