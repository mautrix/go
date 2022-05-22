// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridge

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
)

type CommandProcessor interface {
	Handle(roomID id.RoomID, eventID id.EventID, user User, message string, replyTo id.EventID)
}

type MatrixHandler struct {
	bridge *Bridge
	as     *appservice.AppService
	log    maulogger.Logger

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
		log:    br.Log.Sub("Matrix"),

		TrackEventDuration: noopTrack,
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

func (mx *MatrixHandler) HandleEncryption(evt *event.Event) {
	defer mx.TrackEventDuration(evt.Type)()
	if evt.Content.AsEncryption().Algorithm != id.AlgorithmMegolmV1 {
		return
	}
	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal != nil && !portal.IsEncrypted() {
		mx.log.Debugfln("%s enabled encryption in %s", evt.Sender, evt.RoomID)
		portal.MarkEncrypted()
		if portal.IsPrivateChat() {
			err := mx.as.BotIntent().EnsureJoined(evt.RoomID, appservice.EnsureJoinedParams{BotOverride: portal.MainIntent().Client})
			if err != nil {
				mx.log.Errorfln("Failed to join bot to %s after encryption was enabled: %v", evt.RoomID, err)
			}
		}
	}
}

func (mx *MatrixHandler) joinAndCheckMembers(evt *event.Event, intent *appservice.IntentAPI) *mautrix.RespJoinedMembers {
	resp, err := intent.JoinRoomByID(evt.RoomID)
	if err != nil {
		mx.log.Debugfln("Failed to join room %s as %s with invite from %s: %v", evt.RoomID, intent.UserID, evt.Sender, err)
		return nil
	}

	members, err := intent.JoinedMembers(resp.RoomID)
	if err != nil {
		mx.log.Debugfln("Failed to get members in room %s after accepting invite from %s as %s: %v", resp.RoomID, evt.Sender, intent.UserID, err)
		_, _ = intent.LeaveRoom(resp.RoomID)
		return nil
	}

	if len(members.Joined) < 2 {
		mx.log.Debugln("Leaving empty room", resp.RoomID, "after accepting invite from", evt.Sender, "as", intent.UserID)
		_, _ = intent.LeaveRoom(resp.RoomID)
		return nil
	}
	return members
}

func (mx *MatrixHandler) sendNoticeWithMarkdown(roomID id.RoomID, message string) (*mautrix.RespSendEvent, error) {
	intent := mx.as.BotIntent()
	content := format.RenderMarkdown(message, true, false)
	content.MsgType = event.MsgNotice
	return intent.SendMessageEvent(roomID, event.EventMessage, content)
}

func (mx *MatrixHandler) HandleBotInvite(evt *event.Event) {
	intent := mx.as.BotIntent()

	user := mx.bridge.Child.GetIUser(evt.Sender, true)
	if user == nil {
		return
	}

	members := mx.joinAndCheckMembers(evt, intent)
	if members == nil {
		return
	}

	if user.GetPermissionLevel() <= 0 {
		_, _ = intent.SendNotice(evt.RoomID, "You are not whitelisted to use this bridge.\n"+
			"If you're the owner of this bridge, see the bridge.permissions section in your config file.")
		_, _ = intent.LeaveRoom(evt.RoomID)
		return
	}

	texts := mx.bridge.Config.Bridge.GetManagementRoomTexts()
	_, _ = mx.sendNoticeWithMarkdown(evt.RoomID, texts.Welcome)

	if len(members.Joined) == 2 && (len(user.GetManagementRoomID()) == 0 || evt.Content.AsMember().IsDirect) {
		user.SetManagementRoom(evt.RoomID)
		_, _ = intent.SendNotice(user.GetManagementRoomID(), "This room has been registered as your bridge management/status room.")
		mx.log.Debugln(evt.RoomID, "registered as a management room with", evt.Sender)
	}

	if evt.RoomID == user.GetManagementRoomID() {
		if user.IsLoggedIn() {
			_, _ = mx.sendNoticeWithMarkdown(evt.RoomID, texts.WelcomeConnected)
		} else {
			_, _ = mx.sendNoticeWithMarkdown(evt.RoomID, texts.WelcomeUnconnected)
		}

		additionalHelp := texts.AdditionalHelp
		if len(additionalHelp) > 0 {
			_, _ = mx.sendNoticeWithMarkdown(evt.RoomID, additionalHelp)
		}
	}
}

func (mx *MatrixHandler) HandleGhostInvite(evt *event.Event, inviter User, ghost Ghost) {
	intent := ghost.DefaultIntent()

	if inviter.GetPermissionLevel() < bridgeconfig.PermissionLevelUser {
		mx.log.Debugfln("Rejecting invite for %s from %s to %s: user is not whitelisted", ghost.GetMXID(), evt.Sender, evt.RoomID)
		_, err := intent.LeaveRoom(evt.RoomID, &mautrix.ReqLeave{
			Reason: "You're not whitelisted to use this bridge",
		})
		if err != nil {
			mx.log.Warnfln("Failed to reject invite for %s from %s to %s: %v", ghost.GetMXID(), evt.Sender, evt.RoomID, err)
		}
		return
	} else if !inviter.IsLoggedIn() {
		mx.log.Debugfln("Rejecting invite for %s from %s to %s: user is not logged in", ghost.GetMXID(), evt.Sender, evt.RoomID)
		_, err := intent.LeaveRoom(evt.RoomID, &mautrix.ReqLeave{
			Reason: "You're not logged into this bridge",
		})
		if err != nil {
			mx.log.Warnfln("Failed to reject invite for %s from %s to %s: %v", ghost.GetMXID(), evt.Sender, evt.RoomID, err)
		}
		return
	}

	members := mx.joinAndCheckMembers(evt, intent)
	if members == nil {
		return
	}
	var createEvent event.CreateEventContent
	if err := intent.StateEvent(evt.RoomID, event.StateCreate, "", &createEvent); err != nil {
		mx.log.Warnfln("Failed to check m.room.create event in %s: %v", evt.RoomID, err)
	} else if createEvent.Type != "" {
		mx.log.Warnfln("Non-standard room type %s in %s, leaving room as %s", createEvent.Type, evt.RoomID, ghost.GetMXID())
		_, err = intent.LeaveRoom(evt.RoomID, &mautrix.ReqLeave{
			Reason: "Unsupported room type",
		})
		if err != nil {
			mx.log.Warnfln("Failed to leave %s as %s: %v", evt.RoomID, ghost.GetMXID(), err)
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
		mx.log.Debugln("Leaving multi-user room", evt.RoomID, "as", ghost.GetMXID(), "after accepting invite from", evt.Sender)
		_, _ = intent.SendNotice(evt.RoomID, "Please invite the bridge bot first if you want to bridge to a remote chat.")
		_, _ = intent.LeaveRoom(evt.RoomID)
	} else {
		_, _ = intent.SendNotice(evt.RoomID, "This puppet will remain inactive until this room is bridged to a remote chat.")
	}
}

func (mx *MatrixHandler) HandleMembership(evt *event.Event) {
	if evt.Sender == mx.bridge.Bot.UserID || mx.bridge.Child.IsGhost(evt.Sender) {
		return
	}
	defer mx.TrackEventDuration(evt.Type)()

	if mx.bridge.Crypto != nil {
		mx.bridge.Crypto.HandleMemberEvent(evt)
	}

	content := evt.Content.AsMember()
	if content.Membership == event.MembershipInvite && id.UserID(evt.GetStateKey()) == mx.as.BotMXID() {
		mx.HandleBotInvite(evt)
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
			mx.HandleGhostInvite(evt, user, ghost)
		}
		return
	} else if user.GetPermissionLevel() < bridgeconfig.PermissionLevelUser || !user.IsLoggedIn() {
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
			portal.HandleMatrixLeave(user)
		} else if ghost != nil {
			portal.HandleMatrixKick(user, ghost)
		}
	} else if content.Membership == event.MembershipInvite && !isSelf && ghost != nil {
		portal.HandleMatrixInvite(user, ghost)
	}
	// TODO kicking/inviting non-ghost users users
}

func (mx *MatrixHandler) HandleRoomMetadata(evt *event.Event) {
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

	portal.HandleMatrixMeta(user, evt)
}

const doublePuppetKey = "fi.mau.double_puppet_source"

func (mx *MatrixHandler) shouldIgnoreEvent(evt *event.Event) bool {
	if evt.Sender == mx.bridge.Bot.UserID || mx.bridge.Child.IsGhost(evt.Sender) {
		return true
	}
	user := mx.bridge.Child.GetIUser(evt.Sender, true)
	if user == nil || user.GetPermissionLevel() <= 0 {
		return true
	} else if val, ok := evt.Content.Raw[doublePuppetKey]; ok && val == mx.bridge.Name && user.GetIDoublePuppet() != nil {
		return true
	}
	return false
}

const sessionWaitTimeout = 5 * time.Second

func (mx *MatrixHandler) HandleEncrypted(evt *event.Event) {
	defer mx.TrackEventDuration(evt.Type)()
	if mx.shouldIgnoreEvent(evt) || mx.bridge.Crypto == nil {
		return
	}

	decrypted, err := mx.bridge.Crypto.Decrypt(evt)
	decryptionRetryCount := 0
	if errors.Is(err, NoSessionFound) {
		content := evt.Content.AsEncrypted()
		mx.log.Debugfln("Couldn't find session %s trying to decrypt %s, waiting %d seconds...", content.SessionID, evt.ID, int(sessionWaitTimeout.Seconds()))
		mx.as.SendErrorMessageSendCheckpoint(evt, appservice.StepDecrypted, err, false, decryptionRetryCount)
		decryptionRetryCount++
		if mx.bridge.Crypto.WaitForSession(evt.RoomID, content.SenderKey, content.SessionID, sessionWaitTimeout) {
			mx.log.Debugfln("Got session %s after waiting, trying to decrypt %s again", content.SessionID, evt.ID)
			decrypted, err = mx.bridge.Crypto.Decrypt(evt)
		} else {
			mx.as.SendErrorMessageSendCheckpoint(evt, appservice.StepDecrypted, fmt.Errorf("didn't receive encryption keys"), false, decryptionRetryCount)
			go mx.waitLongerForSession(evt)
			return
		}
	}
	if err != nil {
		mx.as.SendErrorMessageSendCheckpoint(evt, appservice.StepDecrypted, err, true, decryptionRetryCount)

		mx.log.Warnfln("Failed to decrypt %s: %v", evt.ID, err)
		_, _ = mx.bridge.Bot.SendNotice(evt.RoomID, fmt.Sprintf(
			"\u26a0 Your message was not bridged: %v", err))
		return
	}
	mx.as.SendMessageSendCheckpoint(decrypted, appservice.StepDecrypted, decryptionRetryCount)
	mx.bridge.EventProcessor.Dispatch(decrypted)
}

func (mx *MatrixHandler) waitLongerForSession(evt *event.Event) {
	const extendedTimeout = sessionWaitTimeout * 3

	content := evt.Content.AsEncrypted()
	mx.log.Debugfln("Couldn't find session %s trying to decrypt %s, waiting %d more seconds...",
		content.SessionID, evt.ID, int(extendedTimeout.Seconds()))

	go mx.bridge.Crypto.RequestSession(evt.RoomID, content.SenderKey, content.SessionID, evt.Sender, content.DeviceID)

	resp, err := mx.bridge.Bot.SendNotice(evt.RoomID, fmt.Sprintf(
		"\u26a0 Your message was not bridged: the bridge hasn't received the decryption keys. "+
			"The bridge will retry for %d seconds. If this error keeps happening, try restarting your client.",
		int(extendedTimeout.Seconds())))
	if err != nil {
		mx.log.Errorfln("Failed to send decryption error to %s: %v", evt.RoomID, err)
	}
	update := event.MessageEventContent{MsgType: event.MsgNotice}

	if mx.bridge.Crypto.WaitForSession(evt.RoomID, content.SenderKey, content.SessionID, extendedTimeout) {
		mx.log.Debugfln("Got session %s after waiting more, trying to decrypt %s again", content.SessionID, evt.ID)
		decrypted, err := mx.bridge.Crypto.Decrypt(evt)
		if err == nil {
			mx.as.SendMessageSendCheckpoint(decrypted, appservice.StepDecrypted, 2)
			mx.bridge.EventProcessor.Dispatch(decrypted)
			_, _ = mx.bridge.Bot.RedactEvent(evt.RoomID, resp.EventID)
			return
		}
		mx.log.Warnfln("Failed to decrypt %s: %v", evt.ID, err)
		mx.as.SendErrorMessageSendCheckpoint(evt, appservice.StepDecrypted, err, true, 2)
		update.Body = fmt.Sprintf("\u26a0 Your message was not bridged: %v", err)
	} else {
		mx.log.Debugfln("Didn't get %s, giving up on %s", content.SessionID, evt.ID)
		mx.as.SendErrorMessageSendCheckpoint(evt, appservice.StepDecrypted, fmt.Errorf("didn't receive encryption keys"), true, 2)
		update.Body = "\u26a0 Your message was not bridged: the bridge hasn't received the decryption keys. " +
			"If this error keeps happening, try restarting your client."
	}

	newContent := update
	update.NewContent = &newContent
	if resp != nil {
		update.RelatesTo = &event.RelatesTo{
			Type:    event.RelReplace,
			EventID: resp.EventID,
		}
	}
	_, err = mx.bridge.Bot.SendMessageEvent(evt.RoomID, event.EventMessage, &update)
	if err != nil {
		mx.log.Debugfln("Failed to update decryption error notice %s: %v", resp.EventID, err)
	}
}

func (mx *MatrixHandler) HandleMessage(evt *event.Event) {
	defer mx.TrackEventDuration(evt.Type)()
	if mx.shouldIgnoreEvent(evt) {
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
			content.Body = strings.TrimLeft(content.Body[len(commandPrefix):], " ")
		}
		if hasCommandPrefix || evt.RoomID == user.GetManagementRoomID() {
			mx.bridge.CommandProcessor.Handle(evt.RoomID, evt.ID, user, content.Body, content.GetReplyTo())
			return
		}
	}

	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal != nil {
		portal.ReceiveMatrixEvent(user, evt)
	}
}

func (mx *MatrixHandler) HandleReaction(evt *event.Event) {
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
	}
}

func (mx *MatrixHandler) HandleRedaction(evt *event.Event) {
	defer mx.TrackEventDuration(evt.Type)()

	user := mx.bridge.Child.GetIUser(evt.Sender, true)
	if user == nil {
		return
	}

	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal != nil {
		portal.ReceiveMatrixEvent(user, evt)
	}
}

func (mx *MatrixHandler) HandleReceipt(evt *event.Event) {
	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal == nil {
		return
	}

	for eventID, receipts := range *evt.Content.AsReceipt() {
		for userID, receipt := range receipts.Read {
			user := mx.bridge.Child.GetIUser(userID, false)
			if user == nil {
				// Not a bridge user
				continue
			}
			customPuppet := user.GetIDoublePuppet()
			if val, ok := receipt.Extra[doublePuppetKey].(string); ok && customPuppet != nil && val == mx.bridge.Name {
				// Ignore double puppeted read receipts.
				mx.log.Debugfln("Ignoring double puppeted read receipt %+v", evt.Content.Raw)
				// But do start disappearing messages, because the user read the chat
				dp, ok := portal.(DisappearingPortal)
				if ok {
					dp.ScheduleDisappearing()
				}
			} else {
				portal.HandleMatrixReadReceipt(user, eventID, time.UnixMilli(receipt.Timestamp))
			}
		}
	}
}

func (mx *MatrixHandler) HandleTyping(evt *event.Event) {
	portal := mx.bridge.Child.GetIPortal(evt.RoomID)
	if portal == nil {
		return
	}
	portal.HandleMatrixTyping(evt.Content.AsTyping().UserIDs)
}
