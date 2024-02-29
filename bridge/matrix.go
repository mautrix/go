// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/appservice"
	"github.com/element-hq/mautrix-go/bridge/bridgeconfig"
	"github.com/element-hq/mautrix-go/bridge/status"
	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/format"
	"github.com/element-hq/mautrix-go/id"
)

type CommandProcessor interface {
	Handle(ctx context.Context, roomID id.RoomID, eventID id.EventID, user User, message string, replyTo id.EventID)
}

type MatrixHandler struct {
	bridge *Bridge
	as     *appservice.AppService
	log    *zerolog.Logger

	TrackEventDuration func(event.Type) func()
}

func noop() {}

func noopTrack(_ event.Type) func() {
	return noop
}

func NewMatrixHandler(br *Bridge) *MatrixHandler {
	handler := &MatrixHandler{
		bridge: br,
		as:     br.AS,
		log:    br.ZLog,

		TrackEventDuration: noopTrack,
	}
	for evtType := range status.CheckpointTypes {
		br.EventProcessor.On(evtType, handler.sendBridgeCheckpoint)
	}
	br.EventProcessor.On(event.EventMessage, handler.HandleMessage)
	br.EventProcessor.On(event.EventEncrypted, handler.HandleEncrypted)
	br.EventProcessor.On(event.EventSticker, handler.HandleMessage)
	br.EventProcessor.On(event.EventReaction, handler.HandleReaction)
	br.EventProcessor.On(event.EventRedaction, handler.HandleRedaction)
	br.EventProcessor.On(event.StateMember, handler.HandleMembership)
	br.EventProcessor.On(event.StateRoomName, handler.HandleRoomMetadata)
	br.EventProcessor.On(event.StateRoomAvatar, handler.HandleRoomMetadata)
	br.EventProcessor.On(event.StateTopic, handler.HandleRoomMetadata)
	br.EventProcessor.On(event.StateEncryption, handler.HandleEncryption)
	br.EventProcessor.On(event.EphemeralEventReceipt, handler.HandleReceipt)
	br.EventProcessor.On(event.EphemeralEventTyping, handler.HandleTyping)
	return handler
}

func (mx *MatrixHandler) sendBridgeCheckpoint(_ context.Context, evt *event.Event) {
	if !evt.Mautrix.CheckpointSent {
		go mx.bridge.SendMessageSuccessCheckpoint(evt, status.MsgStepBridge, 0)
	}
}

func (mx *MatrixHandler) HandleEncryption(ctx context.Context, evt *event.Event) {
	defer mx.TrackEventDuration(evt.Type)()
	if evt.Content.AsEncryption().Algorithm != id.AlgorithmMegolmV1 {
		return
	}
	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal != nil && !portal.IsEncrypted() {
		mx.log.Debug().
			Str("user_id", evt.Sender.String()).
			Str("room_id", evt.RoomID.String()).
			Msg("Encryption was enabled in room")
		portal.MarkEncrypted()
		if portal.IsPrivateChat() {
			err := mx.as.BotIntent().EnsureJoined(ctx, evt.RoomID, appservice.EnsureJoinedParams{BotOverride: portal.MainIntent().Client})
			if err != nil {
				mx.log.Err(err).
					Str("room_id", evt.RoomID.String()).
					Msg("Failed to join bot to room after encryption was enabled")
			}
		}
	}
}

func (mx *MatrixHandler) joinAndCheckMembers(ctx context.Context, evt *event.Event, intent *appservice.IntentAPI) *mautrix.RespJoinedMembers {
	log := zerolog.Ctx(ctx)
	resp, err := intent.JoinRoomByID(ctx, evt.RoomID)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to join room with invite")
		return nil
	}

	members, err := intent.JoinedMembers(ctx, resp.RoomID)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get members in room after accepting invite, leaving room")
		_, _ = intent.LeaveRoom(ctx, resp.RoomID)
		return nil
	}

	if len(members.Joined) < 2 {
		log.Debug().Msg("Leaving empty room after accepting invite")
		_, _ = intent.LeaveRoom(ctx, resp.RoomID)
		return nil
	}
	return members
}

func (mx *MatrixHandler) sendNoticeWithMarkdown(ctx context.Context, roomID id.RoomID, message string) (*mautrix.RespSendEvent, error) {
	intent := mx.as.BotIntent()
	content := format.RenderMarkdown(message, true, false)
	content.MsgType = event.MsgNotice
	return intent.SendMessageEvent(ctx, roomID, event.EventMessage, content)
}

func (mx *MatrixHandler) HandleBotInvite(ctx context.Context, evt *event.Event) {
	intent := mx.as.BotIntent()

	user := mx.bridge.Child.GetIUser(evt.Sender, true)
	if user == nil {
		return
	}

	members := mx.joinAndCheckMembers(ctx, evt, intent)
	if members == nil {
		return
	}

	if user.GetPermissionLevel() < bridgeconfig.PermissionLevelUser {
		_, _ = intent.SendNotice(ctx, evt.RoomID, "You are not whitelisted to use this bridge.\n"+
			"If you're the owner of this bridge, see the bridge.permissions section in your config file.")
		_, _ = intent.LeaveRoom(ctx, evt.RoomID)
		return
	}

	texts := mx.bridge.Config.Bridge.GetManagementRoomTexts()
	_, _ = mx.sendNoticeWithMarkdown(ctx, evt.RoomID, texts.Welcome)

	if len(members.Joined) == 2 && (len(user.GetManagementRoomID()) == 0 || evt.Content.AsMember().IsDirect) {
		user.SetManagementRoom(evt.RoomID)
		_, _ = intent.SendNotice(ctx, user.GetManagementRoomID(), "This room has been registered as your bridge management/status room.")
		zerolog.Ctx(ctx).Debug().Msg("Registered room as management room with inviter")
	}

	if evt.RoomID == user.GetManagementRoomID() {
		if user.IsLoggedIn() {
			_, _ = mx.sendNoticeWithMarkdown(ctx, evt.RoomID, texts.WelcomeConnected)
		} else {
			_, _ = mx.sendNoticeWithMarkdown(ctx, evt.RoomID, texts.WelcomeUnconnected)
		}

		additionalHelp := texts.AdditionalHelp
		if len(additionalHelp) > 0 {
			_, _ = mx.sendNoticeWithMarkdown(ctx, evt.RoomID, additionalHelp)
		}
	}
}

func (mx *MatrixHandler) HandleGhostInvite(ctx context.Context, evt *event.Event, inviter User, ghost Ghost) {
	log := zerolog.Ctx(ctx)
	intent := ghost.DefaultIntent()

	if inviter.GetPermissionLevel() < bridgeconfig.PermissionLevelUser {
		log.Debug().Msg("Rejecting invite: inviter is not whitelisted")
		_, err := intent.LeaveRoom(ctx, evt.RoomID, &mautrix.ReqLeave{
			Reason: "You're not whitelisted to use this bridge",
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to reject invite")
		}
		return
	} else if !inviter.IsLoggedIn() {
		log.Debug().Msg("Rejecting invite: inviter is not logged in")
		_, err := intent.LeaveRoom(ctx, evt.RoomID, &mautrix.ReqLeave{
			Reason: "You're not logged into this bridge",
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to reject invite")
		}
		return
	}

	members := mx.joinAndCheckMembers(ctx, evt, intent)
	if members == nil {
		return
	}
	var createEvent event.CreateEventContent
	if err := intent.StateEvent(ctx, evt.RoomID, event.StateCreate, "", &createEvent); err != nil {
		log.Warn().Err(err).Msg("Failed to check m.room.create event in room")
	} else if createEvent.Type != "" {
		log.Warn().Str("room_type", string(createEvent.Type)).Msg("Non-standard room type, leaving room")
		_, err = intent.LeaveRoom(ctx, evt.RoomID, &mautrix.ReqLeave{
			Reason: "Unsupported room type",
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to leave room")
		}
		return
	}
	var hasBridgeBot, hasOtherUsers bool
	for mxid, _ := range members.Joined {
		if mxid == intent.UserID || mxid == inviter.GetMXID() {
			continue
		} else if mxid == mx.bridge.Bot.UserID {
			hasBridgeBot = true
		} else {
			hasOtherUsers = true
		}
	}
	if !hasBridgeBot && !hasOtherUsers && evt.Content.AsMember().IsDirect {
		mx.bridge.Child.CreatePrivatePortal(evt.RoomID, inviter, ghost)
	} else if !hasBridgeBot {
		log.Debug().Msg("Leaving multi-user room after accepting invite")
		_, _ = intent.SendNotice(ctx, evt.RoomID, "Please invite the bridge bot first if you want to bridge to a remote chat.")
		_, _ = intent.LeaveRoom(ctx, evt.RoomID)
	} else {
		_, _ = intent.SendNotice(ctx, evt.RoomID, "This puppet will remain inactive until this room is bridged to a remote chat.")
	}
}

func (mx *MatrixHandler) HandleMembership(ctx context.Context, evt *event.Event) {
	if evt.Sender == mx.bridge.Bot.UserID || mx.bridge.Child.IsGhost(evt.Sender) {
		return
	}
	defer mx.TrackEventDuration(evt.Type)()

	if mx.bridge.Crypto != nil {
		mx.bridge.Crypto.HandleMemberEvent(ctx, evt)
	}

	log := mx.log.With().
		Str("sender", evt.Sender.String()).
		Str("target", evt.GetStateKey()).
		Str("room_id", evt.RoomID.String()).
		Logger()
	ctx = log.WithContext(ctx)

	content := evt.Content.AsMember()
	if content.Membership == event.MembershipInvite && id.UserID(evt.GetStateKey()) == mx.as.BotMXID() {
		mx.HandleBotInvite(ctx, evt)
		return
	}

	if mx.shouldIgnoreEvent(evt) {
		return
	}

	user := mx.bridge.Child.GetIUser(evt.Sender, true)
	if user == nil {
		return
	}
	isSelf := id.UserID(evt.GetStateKey()) == evt.Sender
	ghost := mx.bridge.Child.GetIGhost(id.UserID(evt.GetStateKey()))
	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal == nil {
		if ghost != nil && content.Membership == event.MembershipInvite {
			mx.HandleGhostInvite(ctx, evt, user, ghost)
		}
		return
	} else if user.GetPermissionLevel() < bridgeconfig.PermissionLevelUser || !user.IsLoggedIn() {
		return
	}

	mhp, ok := portal.(MembershipHandlingPortal)
	if !ok {
		return
	}

	if content.Membership == event.MembershipLeave {
		if evt.Unsigned.PrevContent != nil {
			_ = evt.Unsigned.PrevContent.ParseRaw(evt.Type)
			prevContent, ok := evt.Unsigned.PrevContent.Parsed.(*event.MemberEventContent)
			if ok && prevContent.Membership != "join" {
				return
			}
		}
		if isSelf {
			mhp.HandleMatrixLeave(user, evt)
		} else if ghost != nil {
			mhp.HandleMatrixKick(user, ghost, evt)
		}
	} else if content.Membership == event.MembershipInvite && !isSelf && ghost != nil {
		mhp.HandleMatrixInvite(user, ghost, evt)
	}
	// TODO kicking/inviting non-ghost users users
}

func (mx *MatrixHandler) HandleRoomMetadata(ctx context.Context, evt *event.Event) {
	defer mx.TrackEventDuration(evt.Type)()
	if mx.shouldIgnoreEvent(evt) {
		return
	}

	user := mx.bridge.Child.GetIUser(evt.Sender, true)
	if user == nil {
		return
	}

	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal == nil || portal.IsPrivateChat() {
		return
	}

	metaPortal, ok := portal.(MetaHandlingPortal)
	if !ok {
		return
	}

	metaPortal.HandleMatrixMeta(user, evt)
}

func (mx *MatrixHandler) shouldIgnoreEvent(evt *event.Event) bool {
	if evt.Sender == mx.bridge.Bot.UserID || mx.bridge.Child.IsGhost(evt.Sender) {
		return true
	}
	user := mx.bridge.Child.GetIUser(evt.Sender, true)
	if user == nil || user.GetPermissionLevel() <= 0 {
		return true
	} else if val, ok := evt.Content.Raw[appservice.DoublePuppetKey]; ok && val == mx.bridge.Name && user.GetIDoublePuppet() != nil {
		return true
	}
	return false
}

const initialSessionWaitTimeout = 3 * time.Second
const extendedSessionWaitTimeout = 22 * time.Second

func (mx *MatrixHandler) sendCryptoStatusError(ctx context.Context, evt *event.Event, editEvent id.EventID, err error, retryCount int, isFinal bool) id.EventID {
	mx.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepDecrypted, err, isFinal, retryCount)

	if mx.bridge.Config.Bridge.EnableMessageStatusEvents() {
		statusEvent := &event.BeeperMessageStatusEventContent{
			// TODO: network
			RelatesTo: event.RelatesTo{
				Type:    event.RelReference,
				EventID: evt.ID,
			},
			Status:  event.MessageStatusRetriable,
			Reason:  event.MessageStatusUndecryptable,
			Error:   err.Error(),
			Message: errorToHumanMessage(err),
		}
		if !isFinal {
			statusEvent.Status = event.MessageStatusPending
		}
		_, sendErr := mx.bridge.Bot.SendMessageEvent(ctx, evt.RoomID, event.BeeperMessageStatus, statusEvent)
		if sendErr != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("Failed to send message status event")
		}
	}
	if mx.bridge.Config.Bridge.EnableMessageErrorNotices() {
		update := event.MessageEventContent{
			MsgType: event.MsgNotice,
			Body:    fmt.Sprintf("\u26a0 Your message was not bridged: %v.", err),
		}
		if errors.Is(err, errNoCrypto) {
			update.Body = "🔒 This bridge has not been configured to support encryption"
		}
		relatable, ok := evt.Content.Parsed.(event.Relatable)
		if editEvent != "" {
			update.SetEdit(editEvent)
		} else if ok && relatable.OptionalGetRelatesTo().GetThreadParent() != "" {
			update.GetRelatesTo().SetThread(relatable.OptionalGetRelatesTo().GetThreadParent(), evt.ID)
		}
		resp, sendErr := mx.bridge.Bot.SendMessageEvent(ctx, evt.RoomID, event.EventMessage, &update)
		if sendErr != nil {
			zerolog.Ctx(ctx).Error().Err(sendErr).Msg("Failed to send decryption error notice")
		} else if resp != nil {
			return resp.EventID
		}
	}
	return ""
}

var (
	errDeviceNotTrusted    = errors.New("your device is not trusted")
	errMessageNotEncrypted = errors.New("unencrypted message")
	errNoDecryptionKeys    = errors.New("the bridge hasn't received the decryption keys")
	errNoCrypto            = errors.New("this bridge has not been configured to support encryption")
)

func errorToHumanMessage(err error) string {
	var withheld *event.RoomKeyWithheldEventContent
	switch {
	case errors.Is(err, errDeviceNotTrusted), errors.Is(err, errNoDecryptionKeys):
		return err.Error()
	case errors.Is(err, UnknownMessageIndex):
		return "the keys received by the bridge can't decrypt the message"
	case errors.Is(err, DuplicateMessageIndex):
		return "your client encrypted multiple messages with the same key"
	case errors.As(err, &withheld):
		if withheld.Code == event.RoomKeyWithheldBeeperRedacted {
			return "your client used an outdated encryption session"
		}
		return "your client refused to share decryption keys with the bridge"
	case errors.Is(err, errMessageNotEncrypted):
		return "the message is not encrypted"
	default:
		return "the bridge failed to decrypt the message"
	}
}

func deviceUnverifiedErrorWithExplanation(trust id.TrustState) error {
	var explanation string
	switch trust {
	case id.TrustStateBlacklisted:
		explanation = "device is blacklisted"
	case id.TrustStateUnset:
		explanation = "unverified"
	case id.TrustStateUnknownDevice:
		explanation = "device info not found"
	case id.TrustStateForwarded:
		explanation = "keys were forwarded from an unknown device"
	case id.TrustStateCrossSignedUntrusted:
		explanation = "cross-signing keys changed after setting up the bridge"
	default:
		return errDeviceNotTrusted
	}
	return fmt.Errorf("%w (%s)", errDeviceNotTrusted, explanation)
}

func copySomeKeys(original, decrypted *event.Event) {
	isScheduled, _ := original.Content.Raw["com.beeper.scheduled"].(bool)
	_, alreadyExists := decrypted.Content.Raw["com.beeper.scheduled"]
	if isScheduled && !alreadyExists {
		decrypted.Content.Raw["com.beeper.scheduled"] = true
	}
}

func (mx *MatrixHandler) postDecrypt(ctx context.Context, original, decrypted *event.Event, retryCount int, errorEventID id.EventID, duration time.Duration) {
	log := zerolog.Ctx(ctx)
	minLevel := mx.bridge.Config.Bridge.GetEncryptionConfig().VerificationLevels.Send
	if decrypted.Mautrix.TrustState < minLevel {
		logEvt := log.Warn().
			Str("user_id", decrypted.Sender.String()).
			Bool("forwarded_keys", decrypted.Mautrix.ForwardedKeys).
			Stringer("device_trust", decrypted.Mautrix.TrustState).
			Stringer("min_trust", minLevel)
		if decrypted.Mautrix.TrustSource != nil {
			dev := decrypted.Mautrix.TrustSource
			logEvt.
				Str("device_id", dev.DeviceID.String()).
				Str("device_signing_key", dev.SigningKey.String())
		} else {
			logEvt.Str("device_id", "unknown")
		}
		logEvt.Msg("Dropping event due to insufficient verification level")
		err := deviceUnverifiedErrorWithExplanation(decrypted.Mautrix.TrustState)
		go mx.sendCryptoStatusError(ctx, decrypted, errorEventID, err, retryCount, true)
		return
	}
	copySomeKeys(original, decrypted)

	mx.bridge.SendMessageSuccessCheckpoint(decrypted, status.MsgStepDecrypted, retryCount)
	decrypted.Mautrix.CheckpointSent = true
	decrypted.Mautrix.DecryptionDuration = duration
	decrypted.Mautrix.EventSource |= event.SourceDecrypted
	mx.bridge.EventProcessor.Dispatch(ctx, decrypted)
	if errorEventID != "" {
		_, _ = mx.bridge.Bot.RedactEvent(ctx, decrypted.RoomID, errorEventID)
	}
}

func (mx *MatrixHandler) HandleEncrypted(ctx context.Context, evt *event.Event) {
	defer mx.TrackEventDuration(evt.Type)()
	if mx.shouldIgnoreEvent(evt) {
		return
	}
	content := evt.Content.AsEncrypted()
	log := zerolog.Ctx(ctx).With().
		Str("event_id", evt.ID.String()).
		Str("session_id", content.SessionID.String()).
		Logger()
	ctx = log.WithContext(ctx)
	if mx.bridge.Crypto == nil {
		go mx.sendCryptoStatusError(ctx, evt, "", errNoCrypto, 0, true)
		return
	}
	log.Debug().Msg("Decrypting received event")

	decryptionStart := time.Now()
	decrypted, err := mx.bridge.Crypto.Decrypt(ctx, evt)
	decryptionRetryCount := 0
	if errors.Is(err, NoSessionFound) {
		decryptionRetryCount = 1
		log.Debug().
			Int("wait_seconds", int(initialSessionWaitTimeout.Seconds())).
			Msg("Couldn't find session, waiting for keys to arrive...")
		mx.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepDecrypted, err, false, 0)
		if mx.bridge.Crypto.WaitForSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, initialSessionWaitTimeout) {
			log.Debug().Msg("Got keys after waiting, trying to decrypt event again")
			decrypted, err = mx.bridge.Crypto.Decrypt(ctx, evt)
		} else {
			go mx.waitLongerForSession(ctx, evt, decryptionStart)
			return
		}
	}
	if err != nil {
		mx.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepDecrypted, err, true, decryptionRetryCount)
		log.Warn().Err(err).Msg("Failed to decrypt event")
		go mx.sendCryptoStatusError(ctx, evt, "", err, decryptionRetryCount, true)
		return
	}
	mx.postDecrypt(ctx, evt, decrypted, decryptionRetryCount, "", time.Since(decryptionStart))
}

func (mx *MatrixHandler) waitLongerForSession(ctx context.Context, evt *event.Event, decryptionStart time.Time) {
	log := zerolog.Ctx(ctx)
	content := evt.Content.AsEncrypted()
	log.Debug().
		Int("wait_seconds", int(extendedSessionWaitTimeout.Seconds())).
		Msg("Couldn't find session, requesting keys and waiting longer...")

	go mx.bridge.Crypto.RequestSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, evt.Sender, content.DeviceID)
	errorEventID := mx.sendCryptoStatusError(ctx, evt, "", fmt.Errorf("%w. The bridge will retry for %d seconds", errNoDecryptionKeys, int(extendedSessionWaitTimeout.Seconds())), 1, false)

	if !mx.bridge.Crypto.WaitForSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, extendedSessionWaitTimeout) {
		log.Debug().Msg("Didn't get session, giving up trying to decrypt event")
		mx.sendCryptoStatusError(ctx, evt, errorEventID, errNoDecryptionKeys, 2, true)
		return
	}

	log.Debug().Msg("Got keys after waiting longer, trying to decrypt event again")
	decrypted, err := mx.bridge.Crypto.Decrypt(ctx, evt)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt event")
		mx.sendCryptoStatusError(ctx, evt, errorEventID, err, 2, true)
		return
	}

	mx.postDecrypt(ctx, evt, decrypted, 2, errorEventID, time.Since(decryptionStart))
}

func (mx *MatrixHandler) HandleMessage(ctx context.Context, evt *event.Event) {
	defer mx.TrackEventDuration(evt.Type)()
	log := zerolog.Ctx(ctx).With().
		Str("event_id", evt.ID.String()).
		Str("room_id", evt.RoomID.String()).
		Str("sender", evt.Sender.String()).
		Logger()
	ctx = log.WithContext(ctx)
	if mx.shouldIgnoreEvent(evt) {
		return
	} else if !evt.Mautrix.WasEncrypted && mx.bridge.Config.Bridge.GetEncryptionConfig().Require {
		log.Warn().Msg("Dropping unencrypted event")
		mx.sendCryptoStatusError(ctx, evt, "", errMessageNotEncrypted, 0, true)
		return
	}

	user := mx.bridge.Child.GetIUser(evt.Sender, true)
	if user == nil {
		return
	}

	content := evt.Content.AsMessage()
	content.RemoveReplyFallback()
	if user.GetPermissionLevel() >= bridgeconfig.PermissionLevelUser && content.MsgType == event.MsgText {
		commandPrefix := mx.bridge.Config.Bridge.GetCommandPrefix()
		hasCommandPrefix := strings.HasPrefix(content.Body, commandPrefix)
		if hasCommandPrefix {
			content.Body = strings.TrimLeft(strings.TrimPrefix(content.Body, commandPrefix), " ")
		}
		if hasCommandPrefix || evt.RoomID == user.GetManagementRoomID() {
			go mx.bridge.CommandProcessor.Handle(ctx, evt.RoomID, evt.ID, user, content.Body, content.RelatesTo.GetReplyTo())
			go mx.bridge.SendMessageSuccessCheckpoint(evt, status.MsgStepCommand, 0)
			if mx.bridge.Config.Bridge.EnableMessageStatusEvents() {
				statusEvent := &event.BeeperMessageStatusEventContent{
					// TODO: network
					RelatesTo: event.RelatesTo{
						Type:    event.RelReference,
						EventID: evt.ID,
					},
					Status: event.MessageStatusSuccess,
				}
				_, sendErr := mx.bridge.Bot.SendMessageEvent(ctx, evt.RoomID, event.BeeperMessageStatus, statusEvent)
				if sendErr != nil {
					log.Warn().Err(sendErr).Msg("Failed to send message status event for command")
				}
			}
			return
		}
	}

	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal != nil {
		portal.ReceiveMatrixEvent(user, evt)
	} else {
		mx.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepRemote, fmt.Errorf("unknown room"), true, 0)
	}
}

func (mx *MatrixHandler) HandleReaction(_ context.Context, evt *event.Event) {
	defer mx.TrackEventDuration(evt.Type)()
	if mx.shouldIgnoreEvent(evt) {
		return
	}

	user := mx.bridge.Child.GetIUser(evt.Sender, true)
	if user == nil || user.GetPermissionLevel() < bridgeconfig.PermissionLevelUser || !user.IsLoggedIn() {
		return
	}

	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal != nil {
		portal.ReceiveMatrixEvent(user, evt)
	} else {
		mx.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepRemote, fmt.Errorf("unknown room"), true, 0)
	}
}

func (mx *MatrixHandler) HandleRedaction(_ context.Context, evt *event.Event) {
	defer mx.TrackEventDuration(evt.Type)()
	if mx.shouldIgnoreEvent(evt) {
		return
	}

	user := mx.bridge.Child.GetIUser(evt.Sender, true)
	if user == nil {
		return
	}

	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal != nil {
		portal.ReceiveMatrixEvent(user, evt)
	} else {
		mx.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepRemote, fmt.Errorf("unknown room"), true, 0)
	}
}

func (mx *MatrixHandler) HandleReceipt(_ context.Context, evt *event.Event) {
	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal == nil {
		return
	}

	rrPortal, ok := portal.(ReadReceiptHandlingPortal)
	if !ok {
		return
	}

	for eventID, receipts := range *evt.Content.AsReceipt() {
		for userID, receipt := range receipts[event.ReceiptTypeRead] {
			user := mx.bridge.Child.GetIUser(userID, false)
			if user == nil {
				// Not a bridge user
				continue
			}
			customPuppet := user.GetIDoublePuppet()
			if val, ok := receipt.Extra[appservice.DoublePuppetKey].(string); ok && customPuppet != nil && val == mx.bridge.Name {
				// Ignore double puppeted read receipts.
				mx.log.Debug().Interface("content", evt.Content.Raw).Msg("Ignoring double-puppeted read receipt")
				// But do start disappearing messages, because the user read the chat
				dp, ok := portal.(DisappearingPortal)
				if ok {
					dp.ScheduleDisappearing()
				}
			} else {
				rrPortal.HandleMatrixReadReceipt(user, eventID, receipt)
			}
		}
	}
}

func (mx *MatrixHandler) HandleTyping(_ context.Context, evt *event.Event) {
	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal == nil {
		return
	}
	typingPortal, ok := portal.(TypingPortal)
	if !ok {
		return
	}
	typingPortal.HandleMatrixTyping(evt.Content.AsTyping().UserIDs)
}
