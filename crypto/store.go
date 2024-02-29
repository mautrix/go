// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
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
	// GetLatestSession returns the session with the highest session ID (lexiographically sorting).
	// It's usually safe to return the most recently added session if sorting by session ID is too difficult.
	GetLatestSession(context.Context, id.SenderKey) (*OlmSession, error)
	// UpdateSession updates a session that has previously been inserted with AddSession.
	UpdateSession(context.Context, id.SenderKey, *OlmSession) error

	// PutGroupSession inserts an inbound Megolm session into the store. If an earlier withhold event has been inserted
	// with PutWithheldGroupSession, this call should replace that. However, PutWithheldGroupSession must not replace
	// sessions inserted with this call.
	PutGroupSession(context.Context, id.RoomID, id.SenderKey, id.SessionID, *InboundGroupSession) error
	// GetGroupSession gets an inbound Megolm session from the store. If the group session has been withheld
	// (i.e. a room key withheld event has been saved with PutWithheldGroupSession), this should return the
	// ErrGroupSessionWithheld error. The caller may use GetWithheldGroupSession to find more details.
	GetGroupSession(context.Context, id.RoomID, id.SenderKey, id.SessionID) (*InboundGroupSession, error)
	// RedactGroupSession removes the session data for the given inbound Megolm session from the store.
	RedactGroupSession(context.Context, id.RoomID, id.SenderKey, id.SessionID, string) error
	// RedactGroupSessions removes the session data for all inbound Megolm sessions from a specific device and/or in a specific room.
	RedactGroupSessions(context.Context, id.RoomID, id.SenderKey, string) ([]id.SessionID, error)
	// RedactExpiredGroupSessions removes the session data for all inbound Megolm sessions that have expired.
	RedactExpiredGroupSessions(context.Context) ([]id.SessionID, error)
	// RedactOutdatedGroupSessions removes the session data for all inbound Megolm sessions that are lacking the expiration metadata.
	RedactOutdatedGroupSessions(context.Context) ([]id.SessionID, error)
	// PutWithheldGroupSession tells the store that a specific Megolm session was withheld.
	PutWithheldGroupSession(context.Context, event.RoomKeyWithheldEventContent) error
	// GetWithheldGroupSession gets the event content that was previously inserted with PutWithheldGroupSession.
	GetWithheldGroupSession(context.Context, id.RoomID, id.SenderKey, id.SessionID) (*event.RoomKeyWithheldEventContent, error)

	// GetGroupSessionsForRoom gets all the inbound Megolm sessions for a specific room. This is used for creating key
	// export files. Unlike GetGroupSession, this should not return any errors about withheld keys.
	GetGroupSessionsForRoom(context.Context, id.RoomID) ([]*InboundGroupSession, error)
	// GetAllGroupSessions gets all the inbound Megolm sessions in the store. This is used for creating key export
	// files. Unlike GetGroupSession, this should not return any errors about withheld keys.
	GetAllGroupSessions(context.Context) ([]*InboundGroupSession, error)

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
	GroupSessions         map[id.RoomID]map[id.SenderKey]map[id.SessionID]*InboundGroupSession
	WithheldGroupSessions map[id.RoomID]map[id.SenderKey]map[id.SessionID]*event.RoomKeyWithheldEventContent
	OutGroupSessions      map[id.RoomID]*OutboundGroupSession
	MessageIndices        map[messageIndexKey]messageIndexValue
	Devices               map[id.UserID]map[id.DeviceID]*id.Device
	CrossSigningKeys      map[id.UserID]map[id.CrossSigningUsage]id.CrossSigningKey
	KeySignatures         map[id.UserID]map[id.Ed25519]map[id.UserID]map[id.Ed25519]string
	OutdatedUsers         map[id.UserID]struct{}
}

var _ Store = (*MemoryStore)(nil)

func NewMemoryStore(saveCallback func() error) *MemoryStore {
	if saveCallback == nil {
		saveCallback = func() error { return nil }
	}
	return &MemoryStore{
		save: saveCallback,

		Sessions:              make(map[id.SenderKey]OlmSessionList),
		GroupSessions:         make(map[id.RoomID]map[id.SenderKey]map[id.SessionID]*InboundGroupSession),
		WithheldGroupSessions: make(map[id.RoomID]map[id.SenderKey]map[id.SessionID]*event.RoomKeyWithheldEventContent),
		OutGroupSessions:      make(map[id.RoomID]*OutboundGroupSession),
		MessageIndices:        make(map[messageIndexKey]messageIndexValue),
		Devices:               make(map[id.UserID]map[id.DeviceID]*id.Device),
		CrossSigningKeys:      make(map[id.UserID]map[id.CrossSigningUsage]id.CrossSigningKey),
		KeySignatures:         make(map[id.UserID]map[id.Ed25519]map[id.UserID]map[id.Ed25519]string),
		OutdatedUsers:         make(map[id.UserID]struct{}),
	}
}

func (gs *MemoryStore) Flush(_ context.Context) error {
	gs.lock.Lock()
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *MemoryStore) GetAccount(_ context.Context) (*OlmAccount, error) {
	return gs.Account, nil
}

func (gs *MemoryStore) PutAccount(_ context.Context, account *OlmAccount) error {
	gs.lock.Lock()
	gs.Account = account
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *MemoryStore) GetSessions(_ context.Context, senderKey id.SenderKey) (OlmSessionList, error) {
	gs.lock.Lock()
	sessions, ok := gs.Sessions[senderKey]
	if !ok {
		sessions = []*OlmSession{}
		gs.Sessions[senderKey] = sessions
	}
	gs.lock.Unlock()
	return sessions, nil
}

func (gs *MemoryStore) AddSession(_ context.Context, senderKey id.SenderKey, session *OlmSession) error {
	gs.lock.Lock()
	sessions, _ := gs.Sessions[senderKey]
	gs.Sessions[senderKey] = append(sessions, session)
	sort.Sort(gs.Sessions[senderKey])
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *MemoryStore) UpdateSession(_ context.Context, _ id.SenderKey, _ *OlmSession) error {
	// we don't need to do anything here because the session is a pointer and already stored in our map
	return gs.save()
}

func (gs *MemoryStore) HasSession(_ context.Context, senderKey id.SenderKey) bool {
	gs.lock.RLock()
	sessions, ok := gs.Sessions[senderKey]
	gs.lock.RUnlock()
	return ok && len(sessions) > 0 && !sessions[0].Expired()
}

func (gs *MemoryStore) GetLatestSession(_ context.Context, senderKey id.SenderKey) (*OlmSession, error) {
	gs.lock.RLock()
	sessions, ok := gs.Sessions[senderKey]
	gs.lock.RUnlock()
	if !ok || len(sessions) == 0 {
		return nil, nil
	}
	return sessions[0], nil
}

func (gs *MemoryStore) getGroupSessions(roomID id.RoomID, senderKey id.SenderKey) map[id.SessionID]*InboundGroupSession {
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

func (gs *MemoryStore) PutGroupSession(_ context.Context, roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, igs *InboundGroupSession) error {
	gs.lock.Lock()
	gs.getGroupSessions(roomID, senderKey)[sessionID] = igs
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *MemoryStore) GetGroupSession(_ context.Context, roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID) (*InboundGroupSession, error) {
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

func (gs *MemoryStore) RedactGroupSession(_ context.Context, roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, reason string) error {
	gs.lock.Lock()
	delete(gs.getGroupSessions(roomID, senderKey), sessionID)
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *MemoryStore) RedactGroupSessions(_ context.Context, roomID id.RoomID, senderKey id.SenderKey, reason string) ([]id.SessionID, error) {
	gs.lock.Lock()
	var sessionIDs []id.SessionID
	if roomID != "" && senderKey != "" {
		sessions := gs.getGroupSessions(roomID, senderKey)
		for sessionID := range sessions {
			sessionIDs = append(sessionIDs, sessionID)
			delete(sessions, sessionID)
		}
	} else if senderKey != "" {
		for _, room := range gs.GroupSessions {
			sessions, ok := room[senderKey]
			if ok {
				for sessionID := range sessions {
					sessionIDs = append(sessionIDs, sessionID)
				}
				delete(room, senderKey)
			}
		}
	} else if roomID != "" {
		room, ok := gs.GroupSessions[roomID]
		if ok {
			for senderKey := range room {
				sessions := room[senderKey]
				for sessionID := range sessions {
					sessionIDs = append(sessionIDs, sessionID)
				}
			}
			delete(gs.GroupSessions, roomID)
		}
	} else {
		return nil, fmt.Errorf("room ID or sender key must be provided for redacting sessions")
	}
	err := gs.save()
	gs.lock.Unlock()
	return sessionIDs, err
}

func (gs *MemoryStore) RedactExpiredGroupSessions(_ context.Context) ([]id.SessionID, error) {
	return nil, fmt.Errorf("not implemented")
}

func (gs *MemoryStore) RedactOutdatedGroupSessions(_ context.Context) ([]id.SessionID, error) {
	return nil, fmt.Errorf("not implemented")
}

func (gs *MemoryStore) getWithheldGroupSessions(roomID id.RoomID, senderKey id.SenderKey) map[id.SessionID]*event.RoomKeyWithheldEventContent {
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

func (gs *MemoryStore) PutWithheldGroupSession(_ context.Context, content event.RoomKeyWithheldEventContent) error {
	gs.lock.Lock()
	gs.getWithheldGroupSessions(content.RoomID, content.SenderKey)[content.SessionID] = &content
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *MemoryStore) GetWithheldGroupSession(_ context.Context, roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID) (*event.RoomKeyWithheldEventContent, error) {
	gs.lock.Lock()
	session, ok := gs.getWithheldGroupSessions(roomID, senderKey)[sessionID]
	gs.lock.Unlock()
	if !ok {
		return nil, nil
	}
	return session, nil
}

func (gs *MemoryStore) GetGroupSessionsForRoom(_ context.Context, roomID id.RoomID) ([]*InboundGroupSession, error) {
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

func (gs *MemoryStore) GetAllGroupSessions(_ context.Context) ([]*InboundGroupSession, error) {
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

func (gs *MemoryStore) AddOutboundGroupSession(_ context.Context, session *OutboundGroupSession) error {
	gs.lock.Lock()
	gs.OutGroupSessions[session.RoomID] = session
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *MemoryStore) UpdateOutboundGroupSession(_ context.Context, _ *OutboundGroupSession) error {
	// we don't need to do anything here because the session is a pointer and already stored in our map
	return gs.save()
}

func (gs *MemoryStore) GetOutboundGroupSession(_ context.Context, roomID id.RoomID) (*OutboundGroupSession, error) {
	gs.lock.RLock()
	session, ok := gs.OutGroupSessions[roomID]
	gs.lock.RUnlock()
	if !ok {
		return nil, nil
	}
	return session, nil
}

func (gs *MemoryStore) RemoveOutboundGroupSession(_ context.Context, roomID id.RoomID) error {
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
	devices, ok := gs.Devices[userID]
	if !ok {
		devices = nil
	}
	gs.lock.RUnlock()
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
	devices, ok := gs.Devices[userID]
	if !ok {
		devices = make(map[id.DeviceID]*id.Device)
		gs.Devices[userID] = devices
	}
	devices[device.DeviceID] = device
	err := gs.save()
	gs.lock.Unlock()
	return err
}

func (gs *MemoryStore) PutDevices(_ context.Context, userID id.UserID, devices map[id.DeviceID]*id.Device) error {
	gs.lock.Lock()
	gs.Devices[userID] = devices
	err := gs.save()
	if err == nil {
		delete(gs.OutdatedUsers, userID)
	}
	gs.lock.Unlock()
	return err
}

func (gs *MemoryStore) FilterTrackedUsers(_ context.Context, users []id.UserID) ([]id.UserID, error) {
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
	return users[:ptr], nil
}

func (gs *MemoryStore) MarkTrackedUsersOutdated(_ context.Context, users []id.UserID) error {
	gs.lock.Lock()
	for _, userID := range users {
		if _, ok := gs.Devices[userID]; ok {
			gs.OutdatedUsers[userID] = struct{}{}
		}
	}
	gs.lock.Unlock()
	return nil
}

func (gs *MemoryStore) GetOutdatedTrackedUsers(_ context.Context) ([]id.UserID, error) {
	gs.lock.RLock()
	users := make([]id.UserID, 0, len(gs.OutdatedUsers))
	for userID := range gs.OutdatedUsers {
		users = append(users, userID)
	}
	gs.lock.RUnlock()
	return users, nil
}

func (gs *MemoryStore) PutCrossSigningKey(_ context.Context, userID id.UserID, usage id.CrossSigningUsage, key id.Ed25519) error {
	gs.lock.RLock()
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
	gs.lock.RUnlock()
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
