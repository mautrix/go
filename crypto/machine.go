// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/element-hq/mautrix-go/crypto/ssss"
	"github.com/element-hq/mautrix-go/id"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/event"
)

// OlmMachine is the main struct for handling Matrix end-to-end encryption.
type OlmMachine struct {
	Client *mautrix.Client
	SSSS   *ssss.Machine
	Log    *zerolog.Logger

	CryptoStore Store
	StateStore  StateStore

	PlaintextMentions bool

	// Never ask the server for keys automatically as a side effect during Megolm decryption.
	DisableDecryptKeyFetching bool

	// Don't mark outbound Olm sessions as shared for devices they were initially sent to.
	DisableSharedGroupSessionTracking bool

	SendKeysMinTrust  id.TrustState
	ShareKeysMinTrust id.TrustState

	AllowKeyShare func(context.Context, *id.Device, event.RequestedKeyInfo) *KeyShareRejection

	account *OlmAccount

	roomKeyRequestFilled            *sync.Map
	keyVerificationTransactionState *sync.Map

	keyWaiters     map[id.SessionID]chan struct{}
	keyWaitersLock sync.Mutex

	devicesToUnwedge     map[id.IdentityKey]bool
	devicesToUnwedgeLock sync.Mutex
	recentlyUnwedged     map[id.IdentityKey]time.Time
	recentlyUnwedgedLock sync.Mutex

	olmLock           sync.Mutex
	megolmEncryptLock sync.Mutex
	megolmDecryptLock sync.Mutex

	otkUploadLock sync.Mutex
	lastOTKUpload time.Time

	CrossSigningKeys    *CrossSigningKeysCache
	crossSigningPubkeys *CrossSigningPublicKeysCache

	crossSigningPubkeysFetched bool

	DeleteOutboundKeysOnAck      bool
	DontStoreOutboundKeys        bool
	DeletePreviousKeysOnReceive  bool
	RatchetKeysOnDecrypt         bool
	DeleteFullyUsedKeysOnDecrypt bool
	DeleteKeysOnDeviceDelete     bool

	DisableDeviceChangeKeyRotation bool

	secretLock      sync.Mutex
	secretListeners map[string]chan<- string
}

// StateStore is used by OlmMachine to get room state information that's needed for encryption.
type StateStore interface {
	// IsEncrypted returns whether a room is encrypted.
	IsEncrypted(context.Context, id.RoomID) (bool, error)
	// GetEncryptionEvent returns the encryption event's content for an encrypted room.
	GetEncryptionEvent(context.Context, id.RoomID) (*event.EncryptionEventContent, error)
	// FindSharedRooms returns the encrypted rooms that another user is also in for a user ID.
	FindSharedRooms(context.Context, id.UserID) ([]id.RoomID, error)
}

// NewOlmMachine creates an OlmMachine with the given client, logger and stores.
func NewOlmMachine(client *mautrix.Client, log *zerolog.Logger, cryptoStore Store, stateStore StateStore) *OlmMachine {
	if log == nil {
		logPtr := zerolog.Nop()
		log = &logPtr
	}
	mach := &OlmMachine{
		Client:      client,
		SSSS:        ssss.NewSSSSMachine(client),
		Log:         log,
		CryptoStore: cryptoStore,
		StateStore:  stateStore,

		SendKeysMinTrust:  id.TrustStateUnset,
		ShareKeysMinTrust: id.TrustStateCrossSignedTOFU,

		roomKeyRequestFilled:            &sync.Map{},
		keyVerificationTransactionState: &sync.Map{},

		keyWaiters: make(map[id.SessionID]chan struct{}),

		devicesToUnwedge: make(map[id.IdentityKey]bool),
		recentlyUnwedged: make(map[id.IdentityKey]time.Time),
		secretListeners:  make(map[string]chan<- string),
	}
	mach.AllowKeyShare = mach.defaultAllowKeyShare
	return mach
}

func (mach *OlmMachine) machOrContextLog(ctx context.Context) *zerolog.Logger {
	log := zerolog.Ctx(ctx)
	if log.GetLevel() == zerolog.Disabled || log == zerolog.DefaultContextLogger {
		return mach.Log
	}
	return log
}

// Load loads the Olm account information from the crypto store. If there's no olm account, a new one is created.
// This must be called before using the machine.
func (mach *OlmMachine) Load(ctx context.Context) (err error) {
	mach.account, err = mach.CryptoStore.GetAccount(ctx)
	if err != nil {
		return
	}
	if mach.account == nil {
		mach.account = NewOlmAccount()
	}
	return nil
}

func (mach *OlmMachine) saveAccount(ctx context.Context) error {
	err := mach.CryptoStore.PutAccount(ctx, mach.account)
	if err != nil {
		mach.Log.Error().Err(err).Msg("Failed to save account")
	}
	return err
}

func (mach *OlmMachine) KeyBackupVersion() id.KeyBackupVersion {
	return mach.account.KeyBackupVersion
}

func (mach *OlmMachine) SetKeyBackupVersion(ctx context.Context, version id.KeyBackupVersion) error {
	mach.account.KeyBackupVersion = version
	return mach.saveAccount(ctx)
}

// FlushStore calls the Flush method of the CryptoStore.
func (mach *OlmMachine) FlushStore(ctx context.Context) error {
	return mach.CryptoStore.Flush(ctx)
}

func (mach *OlmMachine) timeTrace(ctx context.Context, thing string, expectedDuration time.Duration) func() {
	start := time.Now()
	return func() {
		duration := time.Now().Sub(start)
		if duration > expectedDuration {
			zerolog.Ctx(ctx).Warn().
				Str("action", thing).
				Dur("duration", duration).
				Msg("Executing encryption function took longer than expected")
		}
	}
}

// Deprecated: moved to SigningKey.Fingerprint
func Fingerprint(key id.SigningKey) string {
	return key.Fingerprint()
}

// Fingerprint returns the fingerprint of the Olm account that can be used for non-interactive verification.
func (mach *OlmMachine) Fingerprint() string {
	return mach.account.SigningKey().Fingerprint()
}

func (mach *OlmMachine) GetAccount() *OlmAccount {
	return mach.account
}

// OwnIdentity returns this device's id.Device struct
func (mach *OlmMachine) OwnIdentity() *id.Device {
	return &id.Device{
		UserID:      mach.Client.UserID,
		DeviceID:    mach.Client.DeviceID,
		IdentityKey: mach.account.IdentityKey(),
		SigningKey:  mach.account.SigningKey(),
		Trust:       id.TrustStateVerified,
		Deleted:     false,
	}
}

type asEventProcessor interface {
	On(evtType event.Type, handler func(ctx context.Context, evt *event.Event))
	OnOTK(func(ctx context.Context, otk *mautrix.OTKCount))
	OnDeviceList(func(ctx context.Context, lists *mautrix.DeviceLists, since string))
}

func (mach *OlmMachine) AddAppserviceListener(ep asEventProcessor) {
	// ToDeviceForwardedRoomKey and ToDeviceRoomKey should only be present inside encrypted to-device events
	ep.On(event.ToDeviceEncrypted, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceRoomKeyRequest, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceRoomKeyWithheld, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceBeeperRoomKeyAck, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceOrgMatrixRoomKeyWithheld, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationRequest, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationStart, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationAccept, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationKey, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationMAC, mach.HandleToDeviceEvent)
	ep.On(event.ToDeviceVerificationCancel, mach.HandleToDeviceEvent)
	ep.OnOTK(mach.HandleOTKCounts)
	ep.OnDeviceList(mach.HandleDeviceLists)
	mach.Log.Debug().Msg("Added listeners for encryption data coming from appservice transactions")
}

func (mach *OlmMachine) HandleDeviceLists(ctx context.Context, dl *mautrix.DeviceLists, since string) {
	if len(dl.Changed) > 0 {
		traceID := time.Now().Format("15:04:05.000000")
		mach.Log.Debug().
			Str("trace_id", traceID).
			Interface("changes", dl.Changed).
			Msg("Device list changes in /sync")
		mach.FetchKeys(ctx, dl.Changed, false)
		mach.Log.Debug().Str("trace_id", traceID).Msg("Finished handling device list changes")
	}
}

func (mach *OlmMachine) HandleOTKCounts(ctx context.Context, otkCount *mautrix.OTKCount) {
	if (len(otkCount.UserID) > 0 && otkCount.UserID != mach.Client.UserID) || (len(otkCount.DeviceID) > 0 && otkCount.DeviceID != mach.Client.DeviceID) {
		// TODO This log probably needs to be silence-able if someone wants to use encrypted appservices with multiple e2ee sessions
		mach.Log.Warn().
			Str("target_user_id", otkCount.UserID.String()).
			Str("target_device_id", otkCount.DeviceID.String()).
			Msg("Dropping OTK counts targeted to someone else")
		return
	}

	minCount := mach.account.Internal.MaxNumberOfOneTimeKeys() / 2
	if otkCount.SignedCurve25519 < int(minCount) {
		traceID := time.Now().Format("15:04:05.000000")
		log := mach.Log.With().Str("trace_id", traceID).Logger()
		ctx = log.WithContext(ctx)
		log.Debug().
			Int("keys_left", otkCount.Curve25519).
			Msg("Sync response said we have less than 50 signed curve25519 keys left, sharing new ones...")
		err := mach.ShareKeys(ctx, otkCount.SignedCurve25519)
		if err != nil {
			log.Error().Err(err).Msg("Failed to share keys")
		} else {
			log.Debug().Msg("Successfully shared keys")
		}
	}
}

// ProcessSyncResponse processes a single /sync response.
//
// This can be easily registered into a mautrix client using .OnSync():
//
//	client.Syncer.(mautrix.ExtensibleSyncer).OnSync(c.crypto.ProcessSyncResponse)
func (mach *OlmMachine) ProcessSyncResponse(ctx context.Context, resp *mautrix.RespSync, since string) bool {
	mach.HandleDeviceLists(ctx, &resp.DeviceLists, since)

	for _, evt := range resp.ToDevice.Events {
		evt.Type.Class = event.ToDeviceEventType
		err := evt.Content.ParseRaw(evt.Type)
		if err != nil {
			mach.Log.Warn().Str("event_type", evt.Type.Type).Err(err).Msg("Failed to parse to-device event")
			continue
		}
		mach.HandleToDeviceEvent(ctx, evt)
	}

	mach.HandleOTKCounts(ctx, &resp.DeviceOTKCount)
	return true
}

// HandleMemberEvent handles a single membership event.
//
// Currently this is not automatically called, so you must add a listener yourself:
//
//	client.Syncer.(mautrix.ExtensibleSyncer).OnEventType(event.StateMember, c.crypto.HandleMemberEvent)
func (mach *OlmMachine) HandleMemberEvent(ctx context.Context, evt *event.Event) {
	if isEncrypted, err := mach.StateStore.IsEncrypted(ctx, evt.RoomID); err != nil {
		mach.machOrContextLog(ctx).Err(err).Stringer("room_id", evt.RoomID).
			Msg("Failed to check if room is encrypted to handle member event")
		return
	} else if !isEncrypted {
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
	mach.Log.Trace().
		Str("room_id", evt.RoomID.String()).
		Str("user_id", evt.GetStateKey()).
		Str("prev_membership", string(prevContent.Membership)).
		Str("new_membership", string(content.Membership)).
		Msg("Got membership state change, invalidating group session in room")
	err := mach.CryptoStore.RemoveOutboundGroupSession(ctx, evt.RoomID)
	if err != nil {
		mach.Log.Warn().Str("room_id", evt.RoomID.String()).Msg("Failed to invalidate outbound group session")
	}
}

func (mach *OlmMachine) HandleEncryptedEvent(ctx context.Context, evt *event.Event) {
	if _, ok := evt.Content.Parsed.(*event.EncryptedEventContent); !ok {
		mach.machOrContextLog(ctx).Warn().Msg("Passed invalid event to encrypted handler")
		return
	}

	decryptedEvt, err := mach.decryptOlmEvent(ctx, evt)
	if err != nil {
		mach.machOrContextLog(ctx).Error().Err(err).Msg("Failed to decrypt to-device event")
		return
	}

	log := mach.machOrContextLog(ctx).With().
		Str("decrypted_type", decryptedEvt.Type.Type).
		Str("sender_device", decryptedEvt.SenderDevice.String()).
		Str("sender_signing_key", decryptedEvt.Keys.Ed25519.String()).
		Logger()
	log.Trace().Msg("Successfully decrypted to-device event")

	switch decryptedContent := decryptedEvt.Content.Parsed.(type) {
	case *event.RoomKeyEventContent:
		mach.receiveRoomKey(ctx, decryptedEvt, decryptedContent)
		log.Trace().Msg("Handled room key event")
	case *event.ForwardedRoomKeyEventContent:
		if mach.importForwardedRoomKey(ctx, decryptedEvt, decryptedContent) {
			if ch, ok := mach.roomKeyRequestFilled.Load(decryptedContent.SessionID); ok {
				// close channel to notify listener that the key was received
				close(ch.(chan struct{}))
			}
		}
		log.Trace().Msg("Handled forwarded room key event")
	case *event.DummyEventContent:
		log.Debug().Msg("Received encrypted dummy event")
	case *event.SecretSendEventContent:
		mach.receiveSecret(ctx, decryptedEvt, decryptedContent)
		log.Trace().Msg("Handled secret send event")
	default:
		log.Debug().Msg("Unhandled encrypted to-device event")
	}
}

// HandleToDeviceEvent handles a single to-device event. This is automatically called by ProcessSyncResponse, so you
// don't need to add any custom handlers if you use that method.
func (mach *OlmMachine) HandleToDeviceEvent(ctx context.Context, evt *event.Event) {
	if len(evt.ToUserID) > 0 && (evt.ToUserID != mach.Client.UserID || evt.ToDeviceID != mach.Client.DeviceID) {
		// TODO This log probably needs to be silence-able if someone wants to use encrypted appservices with multiple e2ee sessions
		mach.Log.Debug().
			Str("target_user_id", evt.ToUserID.String()).
			Str("target_device_id", evt.ToDeviceID.String()).
			Msg("Dropping to-device event targeted to someone else")
		return
	}
	traceID := time.Now().Format("15:04:05.000000")
	// TODO use context log?
	log := mach.Log.With().
		Str("trace_id", traceID).
		Str("sender", evt.Sender.String()).
		Str("type", evt.Type.Type).
		Logger()
	ctx = log.WithContext(ctx)
	if evt.Type != event.ToDeviceEncrypted {
		log.Debug().Msg("Starting handling to-device event")
	}
	switch content := evt.Content.Parsed.(type) {
	case *event.EncryptedEventContent:
		mach.HandleEncryptedEvent(ctx, evt)
		return
	case *event.RoomKeyRequestEventContent:
		go mach.HandleRoomKeyRequest(ctx, evt.Sender, content)
	case *event.BeeperRoomKeyAckEventContent:
		mach.HandleBeeperRoomKeyAck(ctx, evt.Sender, content)
	case *event.RoomKeyWithheldEventContent:
		mach.HandleRoomKeyWithheld(ctx, content)
	case *event.SecretRequestEventContent:
		if content.Action == event.SecretRequestRequest {
			mach.HandleSecretRequest(ctx, evt.Sender, content)
			log.Trace().Msg("Handled secret request event")
		}
	default:
		deviceID, _ := evt.Content.Raw["device_id"].(string)
		log.Debug().Str("maybe_device_id", deviceID).Msg("Unhandled to-device event")
		return
	}
	log.Debug().Msg("Finished handling to-device event")
}

// GetOrFetchDevice attempts to retrieve the device identity for the given device from the store
// and if it's not found it asks the server for it.
func (mach *OlmMachine) GetOrFetchDevice(ctx context.Context, userID id.UserID, deviceID id.DeviceID) (*id.Device, error) {
	device, err := mach.CryptoStore.GetDevice(ctx, userID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sender device from store: %w", err)
	} else if device != nil {
		return device, nil
	}
	if usersToDevices, err := mach.FetchKeys(ctx, []id.UserID{userID}, true); err != nil {
		return nil, fmt.Errorf("failed to fetch keys: %w", err)
	} else if devices, ok := usersToDevices[userID]; ok {
		if device, ok = devices[deviceID]; ok {
			return device, nil
		}
		return nil, fmt.Errorf("didn't get identity for device %s of %s", deviceID, userID)
	}
	return nil, fmt.Errorf("didn't get any devices for %s", userID)
}

// GetOrFetchDeviceByKey attempts to retrieve the device identity for the device with the given identity key from the
// store and if it's not found it asks the server for it. This returns nil if the server doesn't return a device with
// the given identity key.
func (mach *OlmMachine) GetOrFetchDeviceByKey(ctx context.Context, userID id.UserID, identityKey id.IdentityKey) (*id.Device, error) {
	deviceIdentity, err := mach.CryptoStore.FindDeviceByKey(ctx, userID, identityKey)
	if err != nil || deviceIdentity != nil {
		return deviceIdentity, err
	}
	mach.machOrContextLog(ctx).Debug().
		Str("user_id", userID.String()).
		Str("identity_key", identityKey.String()).
		Msg("Didn't find identity in crypto store, fetching from server")
	devices := mach.LoadDevices(ctx, userID)
	for _, device := range devices {
		if device.IdentityKey == identityKey {
			return device, nil
		}
	}
	return nil, nil
}

// SendEncryptedToDevice sends an Olm-encrypted event to the given user device.
func (mach *OlmMachine) SendEncryptedToDevice(ctx context.Context, device *id.Device, evtType event.Type, content event.Content) error {
	if err := mach.createOutboundSessions(ctx, map[id.UserID]map[id.DeviceID]*id.Device{
		device.UserID: {
			device.DeviceID: device,
		},
	}); err != nil {
		return err
	}

	mach.olmLock.Lock()
	defer mach.olmLock.Unlock()

	olmSess, err := mach.CryptoStore.GetLatestSession(ctx, device.IdentityKey)
	if err != nil {
		return err
	}
	if olmSess == nil {
		return fmt.Errorf("didn't find created outbound session for device %s of %s", device.DeviceID, device.UserID)
	}

	encrypted := mach.encryptOlmEvent(ctx, olmSess, device, evtType, content)
	encryptedContent := &event.Content{Parsed: &encrypted}

	mach.machOrContextLog(ctx).Debug().
		Str("decrypted_type", evtType.Type).
		Str("to_user_id", device.UserID.String()).
		Str("to_device_id", device.DeviceID.String()).
		Str("to_identity_key", device.IdentityKey.String()).
		Str("olm_session_id", olmSess.ID().String()).
		Msg("Sending encrypted to-device event")
	_, err = mach.Client.SendToDevice(ctx, event.ToDeviceEncrypted,
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

func (mach *OlmMachine) createGroupSession(ctx context.Context, senderKey id.SenderKey, signingKey id.Ed25519, roomID id.RoomID, sessionID id.SessionID, sessionKey string, maxAge time.Duration, maxMessages int, isScheduled bool) {
	log := zerolog.Ctx(ctx)
	igs, err := NewInboundGroupSession(senderKey, signingKey, roomID, sessionKey, maxAge, maxMessages, isScheduled)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create inbound group session")
		return
	} else if igs.ID() != sessionID {
		log.Warn().
			Str("expected_session_id", sessionID.String()).
			Str("actual_session_id", igs.ID().String()).
			Msg("Mismatched session ID while creating inbound group session")
		return
	}
	err = mach.CryptoStore.PutGroupSession(ctx, roomID, senderKey, sessionID, igs)
	if err != nil {
		log.Error().Err(err).Str("session_id", sessionID.String()).Msg("Failed to store new inbound group session")
		return
	}
	mach.markSessionReceived(sessionID)
	log.Debug().
		Str("session_id", sessionID.String()).
		Str("sender_key", senderKey.String()).
		Str("max_age", maxAge.String()).
		Int("max_messages", maxMessages).
		Bool("is_scheduled", isScheduled).
		Msg("Received inbound group session")
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
func (mach *OlmMachine) WaitForSession(ctx context.Context, roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, timeout time.Duration) bool {
	mach.keyWaitersLock.Lock()
	ch, ok := mach.keyWaiters[sessionID]
	if !ok {
		ch = make(chan struct{})
		mach.keyWaiters[sessionID] = ch
	}
	mach.keyWaitersLock.Unlock()
	// Handle race conditions where a session appears between the failed decryption and WaitForSession call.
	sess, err := mach.CryptoStore.GetGroupSession(ctx, roomID, senderKey, sessionID)
	if sess != nil || errors.Is(err, ErrGroupSessionWithheld) {
		return true
	}
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		sess, err = mach.CryptoStore.GetGroupSession(ctx, roomID, senderKey, sessionID)
		// Check if the session somehow appeared in the store without telling us
		// We accept withheld sessions as received, as then the decryption attempt will show the error.
		return sess != nil || errors.Is(err, ErrGroupSessionWithheld)
	case <-ctx.Done():
		return false
	}
}

func stringifyArray[T ~string](arr []T) []string {
	strs := make([]string, len(arr))
	for i, v := range arr {
		strs[i] = string(v)
	}
	return strs
}

func (mach *OlmMachine) receiveRoomKey(ctx context.Context, evt *DecryptedOlmEvent, content *event.RoomKeyEventContent) {
	log := zerolog.Ctx(ctx).With().
		Str("algorithm", string(content.Algorithm)).
		Str("session_id", content.SessionID.String()).
		Str("room_id", content.RoomID.String()).
		Logger()
	if content.Algorithm != id.AlgorithmMegolmV1 || evt.Keys.Ed25519 == "" {
		log.Debug().Msg("Ignoring weird room key")
		return
	}

	config, err := mach.StateStore.GetEncryptionEvent(ctx, content.RoomID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get encryption event for room")
	}
	var maxAge time.Duration
	var maxMessages int
	if config != nil {
		maxAge = time.Duration(config.RotationPeriodMillis) * time.Millisecond
		if maxAge == 0 {
			maxAge = 7 * 24 * time.Hour
		}
		maxMessages = config.RotationPeriodMessages
		if maxMessages == 0 {
			maxMessages = 100
		}
	}
	if content.MaxAge != 0 {
		maxAge = time.Duration(content.MaxAge) * time.Millisecond
	}
	if content.MaxMessages != 0 {
		maxMessages = content.MaxMessages
	}
	if mach.DeletePreviousKeysOnReceive && !content.IsScheduled {
		log.Debug().Msg("Redacting previous megolm sessions from sender in room")
		sessionIDs, err := mach.CryptoStore.RedactGroupSessions(ctx, content.RoomID, evt.SenderKey, "received new key from device")
		if err != nil {
			log.Err(err).Msg("Failed to redact previous megolm sessions")
		} else {
			log.Info().
				Strs("session_ids", stringifyArray(sessionIDs)).
				Msg("Redacted previous megolm sessions")
		}
	}
	mach.createGroupSession(ctx, evt.SenderKey, evt.Keys.Ed25519, content.RoomID, content.SessionID, content.SessionKey, maxAge, maxMessages, content.IsScheduled)
}

func (mach *OlmMachine) HandleRoomKeyWithheld(ctx context.Context, content *event.RoomKeyWithheldEventContent) {
	if content.Algorithm != id.AlgorithmMegolmV1 {
		zerolog.Ctx(ctx).Debug().Interface("content", content).Msg("Non-megolm room key withheld event")
		return
	}
	err := mach.CryptoStore.PutWithheldGroupSession(ctx, *content)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Msg("Failed to save room key withheld event")
	}
}

// ShareKeys uploads necessary keys to the server.
//
// If the Olm account hasn't been shared, the account keys will be uploaded.
// If currentOTKCount is less than half of the limit (100 / 2 = 50), enough one-time keys will be uploaded so exactly
// half of the limit is filled.
func (mach *OlmMachine) ShareKeys(ctx context.Context, currentOTKCount int) error {
	log := mach.machOrContextLog(ctx)
	start := time.Now()
	mach.otkUploadLock.Lock()
	defer mach.otkUploadLock.Unlock()
	if mach.lastOTKUpload.Add(1*time.Minute).After(start) || currentOTKCount < 0 {
		log.Debug().Msg("Checking OTK count from server due to suspiciously close share keys requests or negative OTK count")
		resp, err := mach.Client.UploadKeys(ctx, &mautrix.ReqUploadKeys{})
		if err != nil {
			return fmt.Errorf("failed to check current OTK counts: %w", err)
		}
		log.Debug().
			Int("input_count", currentOTKCount).
			Int("server_count", resp.OneTimeKeyCounts.SignedCurve25519).
			Msg("Fetched current OTK count from server")
		currentOTKCount = resp.OneTimeKeyCounts.SignedCurve25519
	}
	var deviceKeys *mautrix.DeviceKeys
	if !mach.account.Shared {
		deviceKeys = mach.account.getInitialKeys(mach.Client.UserID, mach.Client.DeviceID)
		err := mach.CryptoStore.PutDevice(ctx, mach.Client.UserID, &id.Device{
			UserID:      mach.Client.UserID,
			DeviceID:    mach.Client.DeviceID,
			IdentityKey: deviceKeys.Keys.GetCurve25519(mach.Client.DeviceID),
			SigningKey:  deviceKeys.Keys.GetEd25519(mach.Client.DeviceID),
		})
		if err != nil {
			return fmt.Errorf("failed to save initial keys: %w", err)
		}
		log.Debug().Msg("Going to upload initial account keys")
	}
	oneTimeKeys := mach.account.getOneTimeKeys(mach.Client.UserID, mach.Client.DeviceID, currentOTKCount)
	if len(oneTimeKeys) == 0 && deviceKeys == nil {
		log.Debug().Msg("No one-time keys nor device keys got when trying to share keys")
		return nil
	}
	req := &mautrix.ReqUploadKeys{
		DeviceKeys:  deviceKeys,
		OneTimeKeys: oneTimeKeys,
	}
	log.Debug().Int("count", len(oneTimeKeys)).Msg("Uploading one-time keys")
	_, err := mach.Client.UploadKeys(ctx, req)
	if err != nil {
		return err
	}
	mach.lastOTKUpload = time.Now()
	mach.account.Shared = true
	return mach.saveAccount(ctx)
}

func (mach *OlmMachine) ExpiredKeyDeleteLoop(ctx context.Context) {
	log := mach.Log.With().Str("action", "redact expired sessions").Logger()
	for {
		sessionIDs, err := mach.CryptoStore.RedactExpiredGroupSessions(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to redact expired megolm sessions")
		} else if len(sessionIDs) > 0 {
			log.Info().Strs("session_ids", stringifyArray(sessionIDs)).Msg("Redacted expired megolm sessions")
		} else {
			log.Debug().Msg("Didn't find any expired megolm sessions")
		}
		select {
		case <-ctx.Done():
			log.Debug().Msg("Loop stopped")
			return
		case <-time.After(24 * time.Hour):
		}
	}
}
