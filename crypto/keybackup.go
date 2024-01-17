package crypto

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"
)

func (mach *OlmMachine) DownloadAndStoreLatestKeyBackup(ctx context.Context, megolmBackupKey *backup.MegolmBackupKey) error {
	log := mach.machOrContextLog(ctx).With().
		Str("action", "download and store latest key backup").
		Logger()
	versionInfo, err := mach.Client.GetKeyBackupLatestVersion(ctx)
	if err != nil {
		return err
	}

	if versionInfo.Algorithm != id.KeyBackupAlgorithmMegolmBackupV1 {
		return fmt.Errorf("unsupported key backup algorithm: %s", versionInfo.Algorithm)
	}

	log = log.With().
		Int("count", versionInfo.Count).
		Str("etag", versionInfo.ETag).
		Str("key_backup_version", versionInfo.Version).
		Logger()

	if versionInfo.Count == 0 {
		log.Debug().Msg("No keys found in key backup")
		return nil
	}

	userSignatures, ok := versionInfo.AuthData.Signatures[mach.Client.UserID]
	if !ok {
		return fmt.Errorf("no signature from user %s found in key backup", mach.Client.UserID)
	}

	crossSigningPubkeys := mach.GetOwnCrossSigningPublicKeys(ctx)

	signatureVerified := false
	for keyID := range userSignatures {
		keyAlg, keyName := keyID.Parse()
		if keyAlg != id.KeyAlgorithmEd25519 {
			continue
		}
		log := log.With().Str("key_name", keyName).Logger()

		var key id.Ed25519
		if keyName == crossSigningPubkeys.MasterKey.String() {
			key = crossSigningPubkeys.MasterKey
		} else if device, err := mach.GetOrFetchDevice(ctx, mach.Client.UserID, id.DeviceID(keyName)); err != nil {
			log.Warn().Err(err).Msg("Failed to fetch device")
			continue
		} else if !mach.IsDeviceTrusted(device) {
			log.Warn().Err(err).Msg("Device is not trusted")
			continue
		} else {
			key = device.SigningKey
		}

		ok, err = signatures.VerifySignatureJSON(versionInfo.AuthData, mach.Client.UserID, keyName, key)
		if err != nil || !ok {
			log.Warn().Err(err).Stringer("key_id", keyID).Msg("Signature verification failed")
			continue
		} else {
			// One of the signatures is valid, break from the loop.
			signatureVerified = true
			break
		}
	}
	if !signatureVerified {
		return fmt.Errorf("no valid signature from user %s found in key backup", mach.Client.UserID)
	}

	keys, err := mach.Client.GetKeyBackup(ctx, versionInfo.Version)
	if err != nil {
		return err
	}

	var count int

	for roomID, backup := range keys.Rooms {
		for sessionID, keyBackupData := range backup.Sessions {
			sessionData, err := keyBackupData.SessionData.Decrypt(megolmBackupKey)
			if err != nil {
				return err
			}

			err = mach.importRoomKeyFromBackup(ctx, roomID, sessionID, sessionData)
			if err != nil {
				return err
			}
			count++
		}
	}

	log.Info().Int("count", count).Msg("successfully imported sessions from backup")

	return nil
}

func (mach *OlmMachine) importRoomKeyFromBackup(ctx context.Context, roomID id.RoomID, sessionID id.SessionID, keyBackupData *backup.MegolmSessionData) error {
	log := zerolog.Ctx(ctx).With().
		Str("room_id", roomID.String()).
		Str("session_id", sessionID.String()).
		Logger()
	if keyBackupData.Algorithm != id.AlgorithmMegolmV1 {
		return fmt.Errorf("ignoring room key in backup with weird algorithm %s", keyBackupData.Algorithm)
	}

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(keyBackupData.SessionKey)))
	base64.StdEncoding.Encode(encoded, keyBackupData.SessionKey)

	igsInternal, err := olm.InboundGroupSessionImport(encoded)
	if err != nil {
		return fmt.Errorf("failed to import inbound group session: %w sessionid was %s", err, string(encoded))
	} else if igsInternal.ID() != sessionID {
		log.Warn().
			Stringer("actual_session_id", igsInternal.ID()).
			Msg("Mismatched session ID while creating inbound group session from key backup")
		return fmt.Errorf("mismatched session ID while creating inbound group session from key backup")
	}

	var maxAge time.Duration
	var maxMessages int
	if config, err := mach.StateStore.GetEncryptionEvent(ctx, roomID); err != nil {
		log.Error().Err(err).Msg("Failed to get encryption event for room")
	} else if config != nil {
		maxAge = time.Duration(config.RotationPeriodMillis) * time.Millisecond
		maxMessages = config.RotationPeriodMessages
	}

	igs := &InboundGroupSession{
		Internal:         *igsInternal,
		SenderKey:        keyBackupData.SenderKey,
		RoomID:           roomID,
		ForwardingChains: append(keyBackupData.ForwardingKeyChain, keyBackupData.SenderKey.String()),
		id:               sessionID,

		ReceivedAt:  time.Now().UTC(),
		MaxAge:      maxAge.Milliseconds(),
		MaxMessages: maxMessages,
	}
	err = mach.CryptoStore.PutGroupSession(ctx, roomID, keyBackupData.SenderKey, sessionID, igs)
	if err != nil {
		return fmt.Errorf("failed to store new inbound group session: %w", err)
	}
	mach.markSessionReceived(sessionID)
	return nil
}
