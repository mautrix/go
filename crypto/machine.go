// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/crypto/ssss"
	"maunium.net/go/mautrix/id"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

// Logger is a simple logging struct for OlmMachine.
// Implementations are recommended to use fmt.Sprintf and manually add a newline after the message.
type Logger interface {
	Error(message string, args ...interface{})
	Warn(message string, args ...interface{})
	Debug(message string, args ...interface{})
	Trace(message string, args ...interface{})
}

// OlmMachine is the main struct for handling Matrix end-to-end encryption.
type OlmMachine struct {
	Client *mautrix.Client
	SSSS   *ssss.Machine
	Log    Logger

	CryptoStore Store
	StateStore  StateStore

	AllowUnverifiedDevices       bool
	ShareKeysToUnverifiedDevices bool

	AllowKeyShare func(*DeviceIdentity, event.RequestedKeyInfo) *KeyShareRejection

	DefaultSASTimeout time.Duration
	// AcceptVerificationFrom determines whether the machine will accept verification requests from this device.
	AcceptVerificationFrom func(string, *DeviceIdentity, id.RoomID) (VerificationRequestResponse, VerificationHooks)

	account *OlmAccount

	roomKeyRequestFilled            *sync.Map
	keyVerificationTransactionState *sync.Map

	keyWaiters     map[id.SessionID]chan struct{}
	keyWaitersLock sync.Mutex

	olmLock sync.Mutex

	CrossSigningKeys    *CrossSigningKeysCache
	crossSigningPubkeys *CrossSigningPublicKeysCache
}

// StateStore is used by OlmMachine to get room state information that's needed for encryption.
type StateStore interface {
	// IsEncrypted returns whether a room is encrypted.
	IsEncrypted(id.RoomID) bool
	// GetEncryptionEvent returns the encryption event's content for an encrypted room.
	GetEncryptionEvent(id.RoomID) *event.EncryptionEventContent
	// FindSharedRooms returns the encrypted rooms that another user is also in for a user ID.
	FindSharedRooms(id.UserID) []id.RoomID
}

// NewOlmMachine creates an OlmMachine with the given client, logger and stores.
func NewOlmMachine(client *mautrix.Client, log Logger, cryptoStore Store, stateStore StateStore) *OlmMachine {
	mach := &OlmMachine{
		Client:      client,
		SSSS:        ssss.NewSSSSMachine(client),
		Log:         log,
		CryptoStore: cryptoStore,
		StateStore:  stateStore,

		AllowUnverifiedDevices:       true,
		ShareKeysToUnverifiedDevices: false,

		DefaultSASTimeout: 10 * time.Minute,
		AcceptVerificationFrom: func(string, *DeviceIdentity, id.RoomID) (VerificationRequestResponse, VerificationHooks) {
			// Reject requests by default. Users need to override this to return appropriate verification hooks.
			return RejectRequest, nil
		},

		roomKeyRequestFilled:            &sync.Map{},
		keyVerificationTransactionState: &sync.Map{},

		keyWaiters: make(map[id.SessionID]chan struct{}),
	}
	mach.AllowKeyShare = mach.defaultAllowKeyShare
	return mach
}

// Load loads the Olm account information from the crypto store. If there's no olm account, a new one is created.
// This must be called before using the machine.
func (mach *OlmMachine) Load() (err error) {
	mach.account, err = mach.CryptoStore.GetAccount()
	if err != nil {
		return
	}
	if mach.account == nil {
		mach.account = NewOlmAccount()
	}
	return nil
}

func (mach *OlmMachine) saveAccount() {
	err := mach.CryptoStore.PutAccount(mach.account)
	if err != nil {
		mach.Log.Error("Failed to save account: %v", err)
	}
}

// FlushStore calls the Flush method of the CryptoStore.
func (mach *OlmMachine) FlushStore() error {
	return mach.CryptoStore.Flush()
}

func Fingerprint(signingKey id.SigningKey) string {
	spacedSigningKey := make([]byte, len(signingKey)+(len(signingKey)-1)/4)
	var ptr = 0
	for i, chr := range signingKey {
		spacedSigningKey[ptr] = byte(chr)
		ptr++
		if i%4 == 3 {
			spacedSigningKey[ptr] = ' '
			ptr++
		}
	}
	return string(spacedSigningKey)
}

// Fingerprint returns the fingerprint of the Olm account that can be used for non-interactive verification.
func (mach *OlmMachine) Fingerprint() string {
	return Fingerprint(mach.account.SigningKey())
}

// OwnIdentity returns this device's DeviceIdentity struct
func (mach *OlmMachine) OwnIdentity() *DeviceIdentity {
	return &DeviceIdentity{
		UserID:      mach.Client.UserID,
		DeviceID:    mach.Client.DeviceID,
		IdentityKey: mach.account.IdentityKey(),
		SigningKey:  mach.account.SigningKey(),
		Trust:       TrustStateVerified,
		Deleted:     false,
	}
}

func (mach *OlmMachine) AddAppserviceListener(ep *appservice.EventProcessor, az *appservice.AppService) {
	// ToDeviceForwardedRoomKey and ToDeviceRoomKey should only be present inside encrypted to-device events
	ep.On(event.ToDeviceEncrypted, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceRoomKeyRequest, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceRoomKeyWithheld, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceOrgMatrixRoomKeyWithheld, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationRequest, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationStart, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationAccept, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationKey, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationMAC, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationCancel, mach.HandleToDeviceEvent)
	ep.OnOTK(mach.HandleOTKCounts)
	ep.OnDeviceList(mach.HandleDeviceLists)
	mach.Log.Trace("Added listeners for encryption data coming from appservice transactions")
}

func (mach *OlmMachine) HandleDeviceLists(dl *mautrix.DeviceLists, since string) {
	if len(dl.Changed) > 0 {
		mach.Log.Trace("Device list changes in /sync: %v", dl.Changed)
		mach.fetchKeys(dl.Changed, since, false)
	}
}

func (mach *OlmMachine) HandleOTKCounts(otkCount *mautrix.OTKCount) {
	if (len(otkCount.UserID) > 0 && otkCount.UserID != mach.Client.UserID) || (len(otkCount.DeviceID) > 0 && otkCount.DeviceID != mach.Client.DeviceID) {
		// TODO This log probably needs to be silence-able if someone wants to use encrypted appservices with multiple e2ee sessions
		mach.Log.Debug("Dropping OTK counts targeted to %s/%s (not us)", otkCount.UserID, otkCount.DeviceID)
		return
	}

	minCount := mach.account.Internal.MaxNumberOfOneTimeKeys() / 2
	if otkCount.SignedCurve25519 < int(minCount) {
		mach.Log.Debug("Sync response said we have %d signed curve25519 keys left, sharing new ones...", otkCount.SignedCurve25519)
		err := mach.ShareKeys(otkCount.SignedCurve25519)
		if err != nil {
			mach.Log.Error("Failed to share keys: %v", err)
		}
	}
}

// ProcessSyncResponse processes a single /sync response.
//
// This can be easily registered into a mautrix client using .OnSync():
//
//     client.Syncer.(*mautrix.DefaultSyncer).OnSync(c.crypto.ProcessSyncResponse)
func (mach *OlmMachine) ProcessSyncResponse(resp *mautrix.RespSync, since string) bool {
	mach.HandleDeviceLists(&resp.DeviceLists, since)

	for _, evt := range resp.ToDevice.Events {
		evt.Type.Class = event.ToDeviceEventType
		err := evt.Content.ParseRaw(evt.Type)
		if err != nil {
			mach.Log.Warn("Failed to parse to-device event of type %s: %v", evt.Type.Type, err)
			continue
		}
		mach.HandleToDeviceEvent(evt)
	}

	mach.HandleOTKCounts(&resp.DeviceOTKCount)
	return true
}

// HandleMemberEvent handles a single membership event.
//
// Currently this is not automatically called, so you must add a listener yourself:
//
//     client.Syncer.(*mautrix.DefaultSyncer).OnEventType(event.StateMember, c.crypto.HandleMemberEvent)
func (mach *OlmMachine) HandleMemberEvent(evt *event.Event) {
	if !mach.StateStore.IsEncrypted(evt.RoomID) {
		return
	}
	content := evt.Content.AsMember()
	if content == nil {
		return
	}
	var prevContent *event.MemberEventContent
	if evt.Unsigned.PrevContent != nil {
		_ = evt.Unsigned.PrevContent.ParseRaw(evt.Type)
		prevContent = evt.Unsigned.PrevContent.AsMember()
	}
	if prevContent == nil {
		prevContent = &event.MemberEventContent{Membership: "unknown"}
	}
	if prevContent.Membership == content.Membership ||
		(prevContent.Membership == event.MembershipInvite && content.Membership == event.MembershipJoin) ||
		(prevContent.Membership == event.MembershipBan && content.Membership == event.MembershipLeave) ||
		(prevContent.Membership == event.MembershipLeave && content.Membership == event.MembershipBan) {
		return
	}
	mach.Log.Trace("Got membership state event in %s changing %s from %s to %s, invalidating group session", evt.RoomID, evt.GetStateKey(), prevContent.Membership, content.Membership)
	err := mach.CryptoStore.RemoveOutboundGroupSession(evt.RoomID)
	if err != nil {
		mach.Log.Warn("Failed to invalidate outbound group session of %s: %v", evt.RoomID, err)
	}
}

// HandleToDeviceEvent handles a single to-device event. This is automatically called by ProcessSyncResponse, so you
// don't need to add any custom handlers if you use that method.
func (mach *OlmMachine) HandleToDeviceEvent(evt *event.Event) {
	if len(evt.ToUserID) > 0 && (evt.ToUserID != mach.Client.UserID || evt.ToDeviceID != mach.Client.DeviceID) {
		// TODO This log probably needs to be silence-able if someone wants to use encrypted appservices with multiple e2ee sessions
		mach.Log.Debug("Dropping to-device event targeted to %s/%s (not us)", evt.ToUserID, evt.ToDeviceID)
		return
	}
	switch content := evt.Content.Parsed.(type) {
	case *event.EncryptedEventContent:
		mach.Log.Debug("Handling encrypted to-device event from %s/%s", evt.Sender, content.SenderKey)
		decryptedEvt, err := mach.decryptOlmEvent(evt)
		if err != nil {
			mach.Log.Error("Failed to decrypt to-device event: %v", err)
			return
		}
		switch decryptedContent := decryptedEvt.Content.Parsed.(type) {
		case *event.RoomKeyEventContent:
			mach.receiveRoomKey(decryptedEvt, decryptedContent)
		case *event.ForwardedRoomKeyEventContent:
			if mach.importForwardedRoomKey(decryptedEvt, decryptedContent) {
				if ch, ok := mach.roomKeyRequestFilled.Load(decryptedContent.SessionID); ok {
					// close channel to notify listener that the key was received
					close(ch.(chan struct{}))
				}
			}
			// TODO handle m.dummy encrypted to-device event?
		default:
			mach.Log.Debug("Unhandled encrypted to-device event of type %s from %s/%s", decryptedEvt.Type.String(), decryptedEvt.Sender, decryptedEvt.SenderDevice)
		}
	case *event.RoomKeyRequestEventContent:
		mach.handleRoomKeyRequest(evt.Sender, content)
	// verification cases
	case *event.VerificationStartEventContent:
		mach.handleVerificationStart(evt.Sender, content, content.TransactionID, 10*time.Minute, "")
	case *event.VerificationAcceptEventContent:
		mach.handleVerificationAccept(evt.Sender, content, content.TransactionID)
	case *event.VerificationKeyEventContent:
		mach.handleVerificationKey(evt.Sender, content, content.TransactionID)
	case *event.VerificationMacEventContent:
		mach.handleVerificationMAC(evt.Sender, content, content.TransactionID)
	case *event.VerificationCancelEventContent:
		mach.handleVerificationCancel(evt.Sender, content, content.TransactionID)
	case *event.VerificationRequestEventContent:
		mach.handleVerificationRequest(evt.Sender, content, content.TransactionID, "")
	case *event.RoomKeyWithheldEventContent:
		mach.handleRoomKeyWithheld(content)
	default:
		deviceID, _ := evt.Content.Raw["device_id"].(string)
		mach.Log.Trace("Unhandled to-device event of type %s from %s/%s", evt.Type.Type, evt.Sender, deviceID)
	}
}

// GetOrFetchDevice attempts to retrieve the device identity for the given device from the store
// and if it's not found it asks the server for it.
func (mach *OlmMachine) GetOrFetchDevice(userID id.UserID, deviceID id.DeviceID) (*DeviceIdentity, error) {
	// get device identity
	device, err := mach.CryptoStore.GetDevice(userID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sender device from store: %w", err)
	} else if device != nil {
		return device, nil
	}
	// try to fetch if not found
	usersToDevices := mach.fetchKeys([]id.UserID{userID}, "", true)
	if devices, ok := usersToDevices[userID]; ok {
		if device, ok = devices[deviceID]; ok {
			return device, nil
		}
		return nil, fmt.Errorf("didn't get identity for device %s of %s", deviceID, userID)
	}
	return nil, fmt.Errorf("didn't get any devices for %s", userID)
}

// SendEncryptedToDevice sends an Olm-encrypted event to the given user device.
func (mach *OlmMachine) SendEncryptedToDevice(device *DeviceIdentity, evtType event.Type, content event.Content) error {
	// create outbound sessions if missing
	if err := mach.createOutboundSessions(map[id.UserID]map[id.DeviceID]*DeviceIdentity{
		device.UserID: {
			device.DeviceID: device,
		},
	}); err != nil {
		return err
	}

	mach.olmLock.Lock()
	defer mach.olmLock.Unlock()

	// get Olm session
	olmSess, err := mach.CryptoStore.GetLatestSession(device.IdentityKey)
	if err != nil {
		return err
	}
	if olmSess == nil {
		return fmt.Errorf("didn't find created outbound session for device %s of %s", device.DeviceID, device.UserID)
	}

	encrypted := mach.encryptOlmEvent(olmSess, device, evtType, content)
	encryptedContent := &event.Content{Parsed: &encrypted}

	mach.Log.Debug("Sending encrypted to-device event of type %s to %s/%s (identity key: %s, olm session ID: %s)", evtType.Type, device.UserID, device.DeviceID, device.IdentityKey, olmSess.ID())
	_, err = mach.Client.SendToDevice(event.ToDeviceEncrypted,
		&mautrix.ReqSendToDevice{
			Messages: map[id.UserID]map[id.DeviceID]*event.Content{
				device.UserID: {
					device.DeviceID: encryptedContent,
				},
			},
		},
	)

	return err
}

func (mach *OlmMachine) createGroupSession(senderKey id.SenderKey, signingKey id.Ed25519, roomID id.RoomID, sessionID id.SessionID, sessionKey string) {
	igs, err := NewInboundGroupSession(senderKey, signingKey, roomID, sessionKey)
	if err != nil {
		mach.Log.Error("Failed to create inbound group session: %v", err)
		return
	} else if igs.ID() != sessionID {
		mach.Log.Warn("Mismatched session ID while creating inbound group session")
		return
	}
	err = mach.CryptoStore.PutGroupSession(roomID, senderKey, sessionID, igs)
	if err != nil {
		mach.Log.Error("Failed to store new inbound group session: %v", err)
		return
	}
	mach.markSessionReceived(sessionID)
	mach.Log.Debug("Received inbound group session %s / %s / %s", roomID, senderKey, sessionID)
}

func (mach *OlmMachine) markSessionReceived(id id.SessionID) {
	mach.keyWaitersLock.Lock()
	ch, ok := mach.keyWaiters[id]
	if ok {
		close(ch)
		delete(mach.keyWaiters, id)
	}
	mach.keyWaitersLock.Unlock()
}

// WaitForSession waits for the given Megolm session to arrive.
func (mach *OlmMachine) WaitForSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, timeout time.Duration) bool {
	mach.keyWaitersLock.Lock()
	ch, ok := mach.keyWaiters[sessionID]
	if !ok {
		ch := make(chan struct{})
		mach.keyWaiters[sessionID] = ch
	}
	mach.keyWaitersLock.Unlock()
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		sess, err := mach.CryptoStore.GetGroupSession(roomID, senderKey, sessionID)
		// Check if the session somehow appeared in the store without telling us
		// We accept withheld sessions as received, as then the decryption attempt will show the error.
		return sess != nil || errors.Is(err, ErrGroupSessionWithheld)
	}
}

func (mach *OlmMachine) receiveRoomKey(evt *DecryptedOlmEvent, content *event.RoomKeyEventContent) {
	// TODO nio had a comment saying "handle this better" for the case where evt.Keys.Ed25519 is none?
	if content.Algorithm != id.AlgorithmMegolmV1 || evt.Keys.Ed25519 == "" {
		mach.Log.Debug("Ignoring weird room key from %s/%s: alg=%s, ed25519=%s, sessionid=%s, roomid=%s", evt.Sender, evt.SenderDevice, content.Algorithm, evt.Keys.Ed25519, content.SessionID, content.RoomID)
		return
	}

	mach.createGroupSession(evt.SenderKey, evt.Keys.Ed25519, content.RoomID, content.SessionID, content.SessionKey)
}

func (mach *OlmMachine) handleRoomKeyWithheld(content *event.RoomKeyWithheldEventContent) {
	if content.Algorithm != id.AlgorithmMegolmV1 {
		mach.Log.Debug("Non-megolm room key withheld event: %+v", content)
		return
	}
	err := mach.CryptoStore.PutWithheldGroupSession(*content)
	if err != nil {
		mach.Log.Error("Failed to save room key withheld event: %v", err)
	}
}

// ShareKeys uploads necessary keys to the server.
//
// If the Olm account hasn't been shared, the account keys will be uploaded.
// If currentOTKCount is less than half of the limit (100 / 2 = 50), enough one-time keys will be uploaded so exactly
// half of the limit is filled.
func (mach *OlmMachine) ShareKeys(currentOTKCount int) error {
	var deviceKeys *mautrix.DeviceKeys
	if !mach.account.Shared {
		deviceKeys = mach.account.getInitialKeys(mach.Client.UserID, mach.Client.DeviceID)
		mach.Log.Trace("Going to upload initial account keys")
	}
	oneTimeKeys := mach.account.getOneTimeKeys(mach.Client.UserID, mach.Client.DeviceID, currentOTKCount)
	if len(oneTimeKeys) == 0 && deviceKeys == nil {
		mach.Log.Trace("No one-time keys nor device keys got when trying to share keys")
		return nil
	}
	req := &mautrix.ReqUploadKeys{
		DeviceKeys:  deviceKeys,
		OneTimeKeys: oneTimeKeys,
	}
	mach.Log.Trace("Uploading %d one-time keys", len(oneTimeKeys))
	_, err := mach.Client.UploadKeys(req)
	if err != nil {
		return err
	}
	mach.account.Shared = true
	mach.saveAccount()
	mach.Log.Trace("Shared keys and saved account")
	return nil
}
