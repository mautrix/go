// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exsync"
	"golang.org/x/exp/maps"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var ErrGroupSessionWithheld error = &event.RoomKeyWithheldEventContent{}

// Store is used by OlmMachine to store Olm and Megolm sessions, user device lists and message indices.
//
// General implementation details:
// * Get methods should not return errors if the requested data does not exist in the store, they should simply return nil.
// * Update methods may assume that the pointer is the same as what has earlier been added to or fetched from the store.
type Store interface {
	// Flush ensures that everything in the store is persisted to disk.
	// This doesn't have to do anything, e.g. for database-backed implementations that persist everything immediately.
	Flush(context.Context) error

	// PutAccount updates the OlmAccount in the store.
	PutAccount(context.Context, *OlmAccount) error
	// GetAccount returns the OlmAccount in the store that was previously inserted with PutAccount.
	GetAccount(ctx context.Context) (*OlmAccount, error)

	// AddSession inserts an Olm session into the store.
	AddSession(context.Context, id.SenderKey, *OlmSession) error
	// HasSession returns whether or not the store has an Olm session with the given sender key.
	HasSession(context.Context, id.SenderKey) bool
	// GetSessions returns all Olm sessions in the store with the given sender key.
	GetSessions(context.Context, id.SenderKey) (OlmSessionList, error)
	// GetLatestSession returns the most recent session that should be used for encrypting outbound messages.
	// It's usually the one with the most recent successful decryption or the highest ID lexically.
	GetLatestSession(context.Context, id.SenderKey) (*OlmSession, error)
	// GetNewestSessionCreationTS returns the creation timestamp of the most recently created session for the given sender key.
	GetNewestSessionCreationTS(context.Context, id.SenderKey) (time.Time, error)
	// UpdateSession updates a session that has previously been inserted with AddSession.
	UpdateSession(context.Context, id.SenderKey, *OlmSession) error
	// DeleteSession deletes the given session that has been previously inserted with AddSession.
	DeleteSession(context.Context, id.SenderKey, *OlmSession) error

	// PutOlmHash marks a given olm message hash as handled.
	PutOlmHash(context.Context, [32]byte, time.Time) error
	// GetOlmHash gets the time that a given olm hash was handled.
	GetOlmHash(context.Context, [32]byte) (time.Time, error)
	// DeleteOldOlmHashes deletes all olm hashes that were handled before the given time.
	DeleteOldOlmHashes(context.Context, time.Time) error

	// PutGroupSession inserts an inbound Megolm session into the store. If an earlier withhold event has been inserted
	// with PutWithheldGroupSession, this call should replace that. However, PutWithheldGroupSession must not replace
	// sessions inserted with this call.
	PutGroupSession(context.Context, *InboundGroupSession) error
	// GetGroupSession gets an inbound Megolm session from the store. If the group session has been withheld
	// (i.e. a room key withheld event has been saved with PutWithheldGroupSession), this should return the
	// ErrGroupSessionWithheld error. The caller may use GetWithheldGroupSession to find more details.
	GetGroupSession(context.Context, id.RoomID, id.SessionID) (*InboundGroupSession, error)
	// RedactGroupSession removes the session data for the given inbound Megolm session from the store.
	RedactGroupSession(context.Context, id.RoomID, id.SessionID, string) error
	// RedactGroupSessions removes the session data for all inbound Megolm sessions from a specific device and/or in a specific room.
	RedactGroupSessions(context.Context, id.RoomID, id.SenderKey, string) ([]id.SessionID, error)
	// RedactExpiredGroupSessions removes the session data for all inbound Megolm sessions that have expired.
	RedactExpiredGroupSessions(context.Context) ([]id.SessionID, error)
	// RedactOutdatedGroupSessions removes the session data for all inbound Megolm sessions that are lacking the expiration metadata.
	RedactOutdatedGroupSessions(context.Context) ([]id.SessionID, error)
	// PutWithheldGroupSession tells the store that a specific Megolm session was withheld.
	PutWithheldGroupSession(context.Context, event.RoomKeyWithheldEventContent) error
	// GetWithheldGroupSession gets the event content that was previously inserted with PutWithheldGroupSession.
	GetWithheldGroupSession(context.Context, id.RoomID, id.SessionID) (*event.RoomKeyWithheldEventContent, error)

	// GetGroupSessionsForRoom gets all the inbound Megolm sessions for a specific room. This is used for creating key
	// export files. Unlike GetGroupSession, this should not return any errors about withheld keys.
	GetGroupSessionsForRoom(context.Context, id.RoomID) dbutil.RowIter[*InboundGroupSession]
	// GetAllGroupSessions gets all the inbound Megolm sessions in the store. This is used for creating key export
	// files. Unlike GetGroupSession, this should not return any errors about withheld keys.
	GetAllGroupSessions(context.Context) dbutil.RowIter[*InboundGroupSession]
	// GetGroupSessionsWithoutKeyBackupVersion gets all the inbound Megolm sessions in the store that do not match given key backup version.
	GetGroupSessionsWithoutKeyBackupVersion(context.Context, id.KeyBackupVersion) dbutil.RowIter[*InboundGroupSession]

	// AddOutboundGroupSession inserts the given outbound Megolm session into the store.
	//
	// The store should index inserted sessions by the RoomID field to support getting and removing sessions.
	// There will only be one outbound session per room ID at a time.
	AddOutboundGroupSession(context.Context, *OutboundGroupSession) error
	// UpdateOutboundGroupSession updates the given outbound Megolm session in the store.
	UpdateOutboundGroupSession(context.Context, *OutboundGroupSession) error
	// GetOutboundGroupSession gets the stored outbound Megolm session for the given room ID from the store.
	GetOutboundGroupSession(context.Context, id.RoomID) (*OutboundGroupSession, error)
	// RemoveOutboundGroupSession removes the stored outbound Megolm session for the given room ID.
	RemoveOutboundGroupSession(context.Context, id.RoomID) error
	// MarkOutboutGroupSessionShared flags that the currently known device has been shared the keys for the specified session.
	MarkOutboundGroupSessionShared(context.Context, id.UserID, id.IdentityKey, id.SessionID) error
	// IsOutboutGroupSessionShared checks if the specified session has been shared with the device.
	IsOutboundGroupSessionShared(context.Context, id.UserID, id.IdentityKey, id.SessionID) (bool, error)

	// ValidateMessageIndex validates that the given message details aren't from a replay attack.
	//
	// Implementations should store a map from (senderKey, sessionID, index) to (eventID, timestamp), then use that map
	// to check whether or not the message index is valid:
	//
	// * If the map key doesn't exist, the given values should be stored and this should return true.
	// * If the map key exists and the stored values match the given values, this should return true.
	// * If the map key exists, but the stored values do not match the given values, this should return false.
	ValidateMessageIndex(ctx context.Context, senderKey id.SenderKey, sessionID id.SessionID, eventID id.EventID, index uint, timestamp int64) (bool, error)

	// GetDevices returns a map from device ID to id.Device struct containing all devices of a given user.
	GetDevices(context.Context, id.UserID) (map[id.DeviceID]*id.Device, error)
	// GetDevice returns a specific device of a given user.
	GetDevice(context.Context, id.UserID, id.DeviceID) (*id.Device, error)
	// PutDevice stores a single device for a user, replacing it if it exists already.
	PutDevice(context.Context, id.UserID, *id.Device) error
	// PutDevices overrides the stored device list for the given user with the given list.
	PutDevices(context.Context, id.UserID, map[id.DeviceID]*id.Device) error
	// FindDeviceByKey finds a specific device by its identity key.
	FindDeviceByKey(context.Context, id.UserID, id.IdentityKey) (*id.Device, error)
	// FilterTrackedUsers returns a filtered version of the given list that only includes user IDs whose device lists
	// have been stored with PutDevices. A user is considered tracked even if the PutDevices list was empty.
	FilterTrackedUsers(context.Context, []id.UserID) ([]id.UserID, error)
	// MarkTrackedUsersOutdated flags that the device list for given users are outdated.
	MarkTrackedUsersOutdated(context.Context, []id.UserID) error
	// GetOutdatedTrackerUsers gets all tracked users whose devices need to be updated.
	GetOutdatedTrackedUsers(context.Context) ([]id.UserID, error)

	// PutCrossSigningKey stores a cross-signing key of some user along with its usage.
	PutCrossSigningKey(context.Context, id.UserID, id.CrossSigningUsage, id.Ed25519) error
	// GetCrossSigningKeys retrieves a user's stored cross-signing keys.
	GetCrossSigningKeys(context.Context, id.UserID) (map[id.CrossSigningUsage]id.CrossSigningKey, error)
	// PutSignature stores a signature of a cross-signing or device key along with the signer's user ID and key.
	PutSignature(ctx context.Context, signedUser id.UserID, signedKey id.Ed25519, signerUser id.UserID, signerKey id.Ed25519, signature string) error
	// IsKeySignedBy returns whether a cross-signing or device key is signed by the given signer.
	IsKeySignedBy(ctx context.Context, userID id.UserID, key id.Ed25519, signedByUser id.UserID, signedByKey id.Ed25519) (bool, error)
	// DropSignaturesByKey deletes the signatures made by the given user and key from the store. It returns the number of signatures deleted.
	DropSignaturesByKey(context.Context, id.UserID, id.Ed25519) (int64, error)
	// GetSignaturesForKeyBy retrieves the stored signatures for a given cross-signing or device key, by the given signer.
	GetSignaturesForKeyBy(context.Context, id.UserID, id.Ed25519, id.UserID) (map[id.Ed25519]string, error)

	// PutSecret stores a named secret, replacing it if it exists already.
	PutSecret(context.Context, id.Secret, string) error
	// GetSecret returns a named secret.
	GetSecret(context.Context, id.Secret) (string, error)
	// DeleteSecret removes a named secret.
	DeleteSecret(context.Context, id.Secret) error
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

// MemoryStore is a simple in-memory Store implementation. It can optionally have a callback function for saving data,
// but the actual storage must be implemented manually.
type MemoryStore struct {
	lock sync.RWMutex

	save func() error

	Account               *OlmAccount
	Sessions              map[id.SenderKey]OlmSessionList
	GroupSessions         map[id.RoomID]map[id.SessionID]*InboundGroupSession
	WithheldGroupSessions map[id.RoomID]map[id.SessionID]*event.RoomKeyWithheldEventContent
	OutGroupSessions      map[id.RoomID]*OutboundGroupSession
	SharedGroupSessions   map[id.UserID]map[id.IdentityKey]map[id.SessionID]struct{}
	MessageIndices        map[messageIndexKey]messageIndexValue
	Devices               map[id.UserID]map[id.DeviceID]*id.Device
	CrossSigningKeys      map[id.UserID]map[id.CrossSigningUsage]id.CrossSigningKey
	KeySignatures         map[id.UserID]map[id.Ed25519]map[id.UserID]map[id.Ed25519]string
	OutdatedUsers         map[id.UserID]struct{}
	Secrets               map[id.Secret]string
	OlmHashes             *exsync.Set[[32]byte]
}

var _ Store = (*MemoryStore)(nil)

func NewMemoryStore(saveCallback func() error) *MemoryStore {
	if saveCallback == nil {
		saveCallback = func() error { return nil }
	}
	return &MemoryStore{
		save: saveCallback,

		Sessions:              make(map[id.SenderKey]OlmSessionList),
		GroupSessions:         make(map[id.RoomID]map[id.SessionID]*InboundGroupSession),
		WithheldGroupSessions: make(map[id.RoomID]map[id.SessionID]*event.RoomKeyWithheldEventContent),
		OutGroupSessions:      make(map[id.RoomID]*OutboundGroupSession),
		SharedGroupSessions:   make(map[id.UserID]map[id.IdentityKey]map[id.SessionID]struct{}),
		MessageIndices:        make(map[messageIndexKey]messageIndexValue),
		Devices:               make(map[id.UserID]map[id.DeviceID]*id.Device),
		CrossSigningKeys:      make(map[id.UserID]map[id.CrossSigningUsage]id.CrossSigningKey),
		KeySignatures:         make(map[id.UserID]map[id.Ed25519]map[id.UserID]map[id.Ed25519]string),
		OutdatedUsers:         make(map[id.UserID]struct{}),
		Secrets:               make(map[id.Secret]string),
		OlmHashes:             exsync.NewSet[[32]byte](),
	}
}

func (gs *MemoryStore) Flush(_ context.Context) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	return gs.save()
}

func (gs *MemoryStore) GetAccount(_ context.Context) (*OlmAccount, error) {
	return gs.Account, nil
}

func (gs *MemoryStore) PutAccount(_ context.Context, account *OlmAccount) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	gs.Account = account
	return gs.save()
}

func (gs *MemoryStore) GetSessions(_ context.Context, senderKey id.SenderKey) (OlmSessionList, error) {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	sessions, ok := gs.Sessions[senderKey]
	if !ok {
		sessions = []*OlmSession{}
		gs.Sessions[senderKey] = sessions
	}
	return sessions, nil
}

func (gs *MemoryStore) AddSession(_ context.Context, senderKey id.SenderKey, session *OlmSession) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	sessions := gs.Sessions[senderKey]
	gs.Sessions[senderKey] = append(sessions, session)
	sort.Sort(gs.Sessions[senderKey])
	return gs.save()
}

func (gs *MemoryStore) DeleteSession(ctx context.Context, senderKey id.SenderKey, target *OlmSession) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	sessions, ok := gs.Sessions[senderKey]
	if !ok {
		return nil
	}
	gs.Sessions[senderKey] = slices.DeleteFunc(sessions, func(session *OlmSession) bool {
		return session == target
	})
	return gs.save()
}

func (gs *MemoryStore) UpdateSession(_ context.Context, _ id.SenderKey, _ *OlmSession) error {
	// we don't need to do anything here because the session is a pointer and already stored in our map
	return gs.save()
}

func (gs *MemoryStore) HasSession(_ context.Context, senderKey id.SenderKey) bool {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	sessions, ok := gs.Sessions[senderKey]
	return ok && len(sessions) > 0 && !sessions[0].Expired()
}

func (gs *MemoryStore) PutOlmHash(_ context.Context, hash [32]byte, receivedAt time.Time) error {
	gs.OlmHashes.Add(hash)
	return nil
}

func (gs *MemoryStore) GetOlmHash(_ context.Context, hash [32]byte) (time.Time, error) {
	if gs.OlmHashes.Has(hash) {
		// The time isn't that important, so we just return the current time
		return time.Now(), nil
	}
	return time.Time{}, nil
}

func (gs *MemoryStore) DeleteOldOlmHashes(_ context.Context, beforeTS time.Time) error {
	return nil
}

func (gs *MemoryStore) GetLatestSession(_ context.Context, senderKey id.SenderKey) (*OlmSession, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	sessions, ok := gs.Sessions[senderKey]
	if !ok || len(sessions) == 0 {
		return nil, nil
	}
	return sessions[len(sessions)-1], nil
}

func (gs *MemoryStore) GetNewestSessionCreationTS(ctx context.Context, senderKey id.SenderKey) (createdAt time.Time, err error) {
	var sess *OlmSession
	sess, err = gs.GetLatestSession(ctx, senderKey)
	if sess != nil {
		createdAt = sess.CreationTime
	}
	return
}

func (gs *MemoryStore) getGroupSessions(roomID id.RoomID) map[id.SessionID]*InboundGroupSession {
	room, ok := gs.GroupSessions[roomID]
	if !ok {
		room = make(map[id.SessionID]*InboundGroupSession)
		gs.GroupSessions[roomID] = room
	}
	return room
}

func (gs *MemoryStore) PutGroupSession(_ context.Context, igs *InboundGroupSession) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	gs.getGroupSessions(igs.RoomID)[igs.ID()] = igs
	return gs.save()
}

func (gs *MemoryStore) GetGroupSession(_ context.Context, roomID id.RoomID, sessionID id.SessionID) (*InboundGroupSession, error) {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	session, ok := gs.getGroupSessions(roomID)[sessionID]
	if !ok {
		withheld, ok := gs.getWithheldGroupSessions(roomID)[sessionID]
		if ok {
			return nil, fmt.Errorf("%w (%s)", ErrGroupSessionWithheld, withheld.Code)
		}
		return nil, nil
	}
	return session, nil
}

func (gs *MemoryStore) RedactGroupSession(_ context.Context, roomID id.RoomID, sessionID id.SessionID, reason string) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	delete(gs.getGroupSessions(roomID), sessionID)
	return gs.save()
}

func (gs *MemoryStore) RedactGroupSessions(_ context.Context, roomID id.RoomID, senderKey id.SenderKey, reason string) ([]id.SessionID, error) {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	var sessionIDs []id.SessionID
	if roomID != "" && senderKey != "" {
		sessions := gs.getGroupSessions(roomID)
		for sessionID, session := range sessions {
			if session.SenderKey == senderKey {
				sessionIDs = append(sessionIDs, sessionID)
				delete(sessions, sessionID)
			}
		}
	} else if senderKey != "" {
		for _, room := range gs.GroupSessions {
			for sessionID, session := range room {
				if session.SenderKey == senderKey {
					sessionIDs = append(sessionIDs, sessionID)
					delete(room, sessionID)
				}
			}
		}
	} else if roomID != "" {
		sessionIDs = maps.Keys(gs.GroupSessions[roomID])
		delete(gs.GroupSessions, roomID)
	} else {
		return nil, fmt.Errorf("room ID or sender key must be provided for redacting sessions")
	}
	return sessionIDs, gs.save()
}

func (gs *MemoryStore) RedactExpiredGroupSessions(_ context.Context) ([]id.SessionID, error) {
	return nil, fmt.Errorf("not implemented")
}

func (gs *MemoryStore) RedactOutdatedGroupSessions(_ context.Context) ([]id.SessionID, error) {
	return nil, fmt.Errorf("not implemented")
}

func (gs *MemoryStore) getWithheldGroupSessions(roomID id.RoomID) map[id.SessionID]*event.RoomKeyWithheldEventContent {
	room, ok := gs.WithheldGroupSessions[roomID]
	if !ok {
		room = make(map[id.SessionID]*event.RoomKeyWithheldEventContent)
		gs.WithheldGroupSessions[roomID] = room
	}
	return room
}

func (gs *MemoryStore) PutWithheldGroupSession(_ context.Context, content event.RoomKeyWithheldEventContent) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	gs.getWithheldGroupSessions(content.RoomID)[content.SessionID] = &content
	return gs.save()
}

func (gs *MemoryStore) GetWithheldGroupSession(_ context.Context, roomID id.RoomID, sessionID id.SessionID) (*event.RoomKeyWithheldEventContent, error) {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	session, ok := gs.getWithheldGroupSessions(roomID)[sessionID]
	if !ok {
		return nil, nil
	}
	return session, nil
}

func (gs *MemoryStore) GetGroupSessionsForRoom(_ context.Context, roomID id.RoomID) dbutil.RowIter[*InboundGroupSession] {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	room, ok := gs.GroupSessions[roomID]
	if !ok {
		return nil
	}
	return dbutil.NewSliceIter(maps.Values(room))
}

func (gs *MemoryStore) GetAllGroupSessions(_ context.Context) dbutil.RowIter[*InboundGroupSession] {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	var result []*InboundGroupSession
	for _, room := range gs.GroupSessions {
		result = append(result, maps.Values(room)...)
	}
	return dbutil.NewSliceIter(result)
}

func (gs *MemoryStore) GetGroupSessionsWithoutKeyBackupVersion(_ context.Context, version id.KeyBackupVersion) dbutil.RowIter[*InboundGroupSession] {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	var result []*InboundGroupSession
	for _, room := range gs.GroupSessions {
		for _, session := range room {
			if session.KeyBackupVersion != version {
				result = append(result, session)
			}
		}
	}
	return dbutil.NewSliceIter(result)
}

func (gs *MemoryStore) AddOutboundGroupSession(_ context.Context, session *OutboundGroupSession) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	gs.OutGroupSessions[session.RoomID] = session
	return gs.save()
}

func (gs *MemoryStore) UpdateOutboundGroupSession(_ context.Context, _ *OutboundGroupSession) error {
	// we don't need to do anything here because the session is a pointer and already stored in our map
	return gs.save()
}

func (gs *MemoryStore) GetOutboundGroupSession(_ context.Context, roomID id.RoomID) (*OutboundGroupSession, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	session, ok := gs.OutGroupSessions[roomID]
	if !ok {
		return nil, nil
	}
	return session, nil
}

func (gs *MemoryStore) RemoveOutboundGroupSession(_ context.Context, roomID id.RoomID) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	session, ok := gs.OutGroupSessions[roomID]
	if !ok || session == nil {
		return nil
	}
	delete(gs.OutGroupSessions, roomID)
	return nil
}

func (gs *MemoryStore) MarkOutboundGroupSessionShared(_ context.Context, userID id.UserID, identityKey id.IdentityKey, sessionID id.SessionID) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()

	if _, ok := gs.SharedGroupSessions[userID]; !ok {
		gs.SharedGroupSessions[userID] = make(map[id.IdentityKey]map[id.SessionID]struct{})
	}
	identities := gs.SharedGroupSessions[userID]

	if _, ok := identities[identityKey]; !ok {
		identities[identityKey] = make(map[id.SessionID]struct{})
	}

	identities[identityKey][sessionID] = struct{}{}

	return nil
}

func (gs *MemoryStore) IsOutboundGroupSessionShared(_ context.Context, userID id.UserID, identityKey id.IdentityKey, sessionID id.SessionID) (isShared bool, err error) {
	gs.lock.Lock()
	defer gs.lock.Unlock()

	if _, ok := gs.SharedGroupSessions[userID]; !ok {
		return
	}
	identities := gs.SharedGroupSessions[userID]

	if _, ok := identities[identityKey]; !ok {
		return
	}

	_, isShared = identities[identityKey][sessionID]
	return
}

func (gs *MemoryStore) ValidateMessageIndex(_ context.Context, senderKey id.SenderKey, sessionID id.SessionID, eventID id.EventID, index uint, timestamp int64) (bool, error) {
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
		return true, nil
	}
	if val.EventID != eventID || val.Timestamp != timestamp {
		return false, nil
	}
	return true, nil
}

func (gs *MemoryStore) GetDevices(_ context.Context, userID id.UserID) (map[id.DeviceID]*id.Device, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	devices, ok := gs.Devices[userID]
	if !ok {
		devices = nil
	}
	return devices, nil
}

func (gs *MemoryStore) GetDevice(_ context.Context, userID id.UserID, deviceID id.DeviceID) (*id.Device, error) {
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

func (gs *MemoryStore) FindDeviceByKey(_ context.Context, userID id.UserID, identityKey id.IdentityKey) (*id.Device, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	devices, ok := gs.Devices[userID]
	if !ok {
		return nil, nil
	}
	for _, device := range devices {
		if device.IdentityKey == identityKey {
			return device, nil
		}
	}
	return nil, nil
}

func (gs *MemoryStore) PutDevice(_ context.Context, userID id.UserID, device *id.Device) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	devices, ok := gs.Devices[userID]
	if !ok {
		devices = make(map[id.DeviceID]*id.Device)
		gs.Devices[userID] = devices
	}
	devices[device.DeviceID] = device
	return gs.save()
}

func (gs *MemoryStore) PutDevices(_ context.Context, userID id.UserID, devices map[id.DeviceID]*id.Device) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	gs.Devices[userID] = devices
	err := gs.save()
	if err == nil {
		delete(gs.OutdatedUsers, userID)
	}
	return err
}

func (gs *MemoryStore) FilterTrackedUsers(_ context.Context, users []id.UserID) ([]id.UserID, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	var ptr int
	for _, userID := range users {
		_, ok := gs.Devices[userID]
		if ok {
			users[ptr] = userID
			ptr++
		}
	}
	return users[:ptr], nil
}

func (gs *MemoryStore) MarkTrackedUsersOutdated(_ context.Context, users []id.UserID) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	for _, userID := range users {
		if _, ok := gs.Devices[userID]; ok {
			gs.OutdatedUsers[userID] = struct{}{}
		}
	}
	return nil
}

func (gs *MemoryStore) GetOutdatedTrackedUsers(_ context.Context) ([]id.UserID, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	users := make([]id.UserID, 0, len(gs.OutdatedUsers))
	for userID := range gs.OutdatedUsers {
		users = append(users, userID)
	}
	return users, nil
}

func (gs *MemoryStore) PutCrossSigningKey(_ context.Context, userID id.UserID, usage id.CrossSigningUsage, key id.Ed25519) error {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	userKeys, ok := gs.CrossSigningKeys[userID]
	if !ok {
		userKeys = make(map[id.CrossSigningUsage]id.CrossSigningKey)
		gs.CrossSigningKeys[userID] = userKeys
	}
	existing, ok := userKeys[usage]
	if ok {
		existing.Key = key
		userKeys[usage] = existing
	} else {
		userKeys[usage] = id.CrossSigningKey{
			Key:   key,
			First: key,
		}
	}
	err := gs.save()
	return err
}

func (gs *MemoryStore) GetCrossSigningKeys(_ context.Context, userID id.UserID) (map[id.CrossSigningUsage]id.CrossSigningKey, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	keys, ok := gs.CrossSigningKeys[userID]
	if !ok {
		return map[id.CrossSigningUsage]id.CrossSigningKey{}, nil
	}
	return keys, nil
}

func (gs *MemoryStore) PutSignature(_ context.Context, signedUserID id.UserID, signedKey id.Ed25519, signerUserID id.UserID, signerKey id.Ed25519, signature string) error {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
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
	return gs.save()
}

func (gs *MemoryStore) GetSignaturesForKeyBy(_ context.Context, userID id.UserID, key id.Ed25519, signerID id.UserID) (map[id.Ed25519]string, error) {
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

func (gs *MemoryStore) IsKeySignedBy(ctx context.Context, userID id.UserID, key id.Ed25519, signerID id.UserID, signerKey id.Ed25519) (bool, error) {
	sigs, err := gs.GetSignaturesForKeyBy(ctx, userID, key, signerID)
	if err != nil {
		return false, err
	}
	_, ok := sigs[signerKey]
	return ok, nil
}

func (gs *MemoryStore) DropSignaturesByKey(_ context.Context, userID id.UserID, key id.Ed25519) (int64, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	var count int64
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
	return count, nil
}

func (gs *MemoryStore) PutSecret(_ context.Context, name id.Secret, value string) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	gs.Secrets[name] = value
	return nil
}

func (gs *MemoryStore) GetSecret(_ context.Context, name id.Secret) (string, error) {
	gs.lock.RLock()
	defer gs.lock.RUnlock()
	return gs.Secrets[name], nil
}

func (gs *MemoryStore) DeleteSecret(_ context.Context, name id.Secret) error {
	gs.lock.Lock()
	defer gs.lock.Unlock()
	delete(gs.Secrets, name)
	return nil
}
