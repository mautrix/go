// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exfmt"
	"go.mau.fi/util/exslices"
	"go.mau.fi/util/variationselector"
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type portalMatrixEvent struct {
	evt    *event.Event
	sender *User
}

type portalRemoteEvent struct {
	evt    RemoteEvent
	source *UserLogin
}

func (pme *portalMatrixEvent) isPortalEvent() {}
func (pre *portalRemoteEvent) isPortalEvent() {}

type portalEvent interface {
	isPortalEvent()
}

type Portal struct {
	*database.Portal
	Bridge *Bridge
	Log    zerolog.Logger
	Parent *Portal
	Relay  *UserLogin

	currentlyTyping       []id.UserID
	currentlyTypingLogins map[id.UserID]*UserLogin
	currentlyTypingLock   sync.Mutex

	roomCreateLock sync.Mutex

	events chan portalEvent
}

const PortalEventBuffer = 64

func (br *Bridge) loadPortal(ctx context.Context, dbPortal *database.Portal, queryErr error, key *networkid.PortalKey) (*Portal, error) {
	if queryErr != nil {
		return nil, fmt.Errorf("failed to query db: %w", queryErr)
	}
	if dbPortal == nil {
		if key == nil {
			return nil, nil
		}
		dbPortal = &database.Portal{
			BridgeID:  br.ID,
			PortalKey: *key,
		}
		err := br.DB.Portal.Insert(ctx, dbPortal)
		if err != nil {
			return nil, fmt.Errorf("failed to insert new portal: %w", err)
		}
	}
	portal := &Portal{
		Portal: dbPortal,
		Bridge: br,

		events: make(chan portalEvent, PortalEventBuffer),

		currentlyTypingLogins: make(map[id.UserID]*UserLogin),
	}
	br.portalsByKey[portal.PortalKey] = portal
	if portal.MXID != "" {
		br.portalsByMXID[portal.MXID] = portal
	}
	var err error
	if portal.ParentID != "" {
		portal.Parent, err = br.unlockedGetPortalByID(ctx, networkid.PortalKey{ID: portal.ParentID}, false)
		if err != nil {
			return nil, fmt.Errorf("failed to load parent portal (%s): %w", portal.ParentID, err)
		}
	}
	if portal.RelayLoginID != "" {
		portal.Relay, err = br.unlockedGetExistingUserLoginByID(ctx, portal.RelayLoginID)
		if err != nil {
			return nil, fmt.Errorf("failed to load relay login (%s): %w", portal.RelayLoginID, err)
		}
	}
	portal.updateLogger()
	go portal.eventLoop()
	return portal, nil
}

func (portal *Portal) updateLogger() {
	logWith := portal.Bridge.Log.With().Str("portal_id", string(portal.ID))
	if portal.MXID != "" {
		logWith = logWith.Stringer("portal_mxid", portal.MXID)
	}
	portal.Log = logWith.Logger()
}

func (br *Bridge) unlockedGetPortalByID(ctx context.Context, id networkid.PortalKey, onlyIfExists bool) (*Portal, error) {
	cached, ok := br.portalsByKey[id]
	if ok {
		return cached, nil
	}
	idPtr := &id
	if onlyIfExists {
		idPtr = nil
	}
	db, err := br.DB.Portal.GetByID(ctx, id)
	return br.loadPortal(ctx, db, err, idPtr)
}

func (br *Bridge) GetPortalByMXID(ctx context.Context, mxid id.RoomID) (*Portal, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	cached, ok := br.portalsByMXID[mxid]
	if ok {
		return cached, nil
	}
	db, err := br.DB.Portal.GetByMXID(ctx, mxid)
	return br.loadPortal(ctx, db, err, nil)
}

func (br *Bridge) GetPortalByID(ctx context.Context, id networkid.PortalKey) (*Portal, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.unlockedGetPortalByID(ctx, id, false)
}

func (br *Bridge) GetExistingPortalByID(ctx context.Context, id networkid.PortalKey) (*Portal, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	if id.Receiver == "" {
		return br.unlockedGetPortalByID(ctx, id, true)
	}
	cached, ok := br.portalsByKey[id]
	if ok {
		return cached, nil
	}
	cached, ok = br.portalsByKey[networkid.PortalKey{ID: id.ID}]
	if ok {
		return cached, nil
	}
	db, err := br.DB.Portal.GetByIDWithUncertainReceiver(ctx, id)
	return br.loadPortal(ctx, db, err, nil)
}

func (portal *Portal) queueEvent(ctx context.Context, evt portalEvent) {
	select {
	case portal.events <- evt:
	default:
		zerolog.Ctx(ctx).Error().
			Str("portal_id", string(portal.ID)).
			Msg("Portal event channel is full")
	}
}

func (portal *Portal) eventLoop() {
	for rawEvt := range portal.events {
		switch evt := rawEvt.(type) {
		case *portalMatrixEvent:
			portal.handleMatrixEvent(evt.sender, evt.evt)
		case *portalRemoteEvent:
			portal.handleRemoteEvent(evt.source, evt.evt)
		default:
			panic(fmt.Errorf("illegal type %T in eventLoop", evt))
		}
	}
}

func (portal *Portal) FindPreferredLogin(ctx context.Context, user *User, allowRelay bool) (*UserLogin, *database.UserPortal, error) {
	logins, err := portal.Bridge.DB.UserPortal.GetAllForUserInPortal(ctx, user.MXID, portal.PortalKey)
	if err != nil {
		return nil, nil, err
	}
	portal.Bridge.cacheLock.Lock()
	defer portal.Bridge.cacheLock.Unlock()
	for _, up := range logins {
		login, ok := user.logins[up.LoginID]
		if ok && login.Client != nil {
			return login, up, nil
		}
	}
	if !allowRelay {
		return nil, nil, ErrNotLoggedIn
	}
	// Portal has relay, use it
	if portal.Relay != nil {
		return nil, nil, nil
	}
	var firstLogin *UserLogin
	for _, login := range user.logins {
		firstLogin = login
		break
	}
	if firstLogin != nil {
		zerolog.Ctx(ctx).Warn().
			Str("chosen_login_id", string(firstLogin.ID)).
			Msg("No usable user portal rows found, returning random login")
		return firstLogin, nil, nil
	} else {
		return nil, nil, ErrNotLoggedIn
	}
}

func (portal *Portal) sendSuccessStatus(ctx context.Context, evt *event.Event) {
	portal.Bridge.Matrix.SendMessageStatus(ctx, &MessageStatus{Status: event.MessageStatusSuccess}, StatusEventInfoFromEvent(evt))
}

func (portal *Portal) sendErrorStatus(ctx context.Context, evt *event.Event, err error) {
	status := WrapErrorInStatus(err)
	if status.Status == "" {
		status.Status = event.MessageStatusRetriable
	}
	if status.ErrorReason == "" {
		status.ErrorReason = event.MessageStatusGenericError
	}
	if status.InternalError == nil {
		status.InternalError = err
	}
	portal.Bridge.Matrix.SendMessageStatus(ctx, &status, StatusEventInfoFromEvent(evt))
}

func (portal *Portal) handleMatrixEvent(sender *User, evt *event.Event) {
	if evt.Mautrix.EventSource&event.SourceEphemeral != 0 {
		switch evt.Type {
		case event.EphemeralEventReceipt:
			portal.handleMatrixReceipts(evt)
		case event.EphemeralEventTyping:
			portal.handleMatrixTyping(evt)
		}
		return
	}
	log := portal.Log.With().
		Str("action", "handle matrix event").
		Str("event_type", evt.Type.Type).
		Stringer("event_id", evt.ID).
		Stringer("sender", sender.MXID).
		Logger()
	ctx := log.WithContext(context.TODO())
	login, _, err := portal.FindPreferredLogin(ctx, sender, true)
	if err != nil {
		log.Err(err).Msg("Failed to get user login to handle Matrix event")
		if errors.Is(err, ErrNotLoggedIn) {
			portal.sendErrorStatus(ctx, evt, WrapErrorInStatus(err).WithMessage("You're not logged in").WithIsCertain(true).WithSendNotice(true))
		} else {
			portal.sendErrorStatus(ctx, evt, WrapErrorInStatus(err).WithMessage("Failed to get login to handle event").WithIsCertain(true).WithSendNotice(true))
		}
		return
	}
	var origSender *OrigSender
	if login == nil {
		login = portal.Relay
		origSender = &OrigSender{
			User: sender,
		}

		memberInfo, err := portal.Bridge.Matrix.GetMemberInfo(ctx, portal.MXID, sender.MXID)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to get member info for user being relayed")
		} else if memberInfo != nil {
			origSender.MemberEventContent = *memberInfo
		}
	}
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("login_id", string(login.ID))
	})
	switch evt.Type {
	case event.EventMessage, event.EventSticker:
		portal.handleMatrixMessage(ctx, login, origSender, evt)
	case event.EventReaction:
		if origSender != nil {
			log.Debug().Msg("Ignoring reaction event from relayed user")
			portal.sendErrorStatus(ctx, evt, ErrIgnoringReactionFromRelayedUser)
			return
		}
		portal.handleMatrixReaction(ctx, login, evt)
	case event.EventRedaction:
		portal.handleMatrixRedaction(ctx, login, origSender, evt)
	case event.StateRoomName:
		handleMatrixRoomMeta(portal, ctx, login, origSender, evt, RoomNameHandlingNetworkAPI.HandleMatrixRoomName)
	case event.StateTopic:
		handleMatrixRoomMeta(portal, ctx, login, origSender, evt, RoomTopicHandlingNetworkAPI.HandleMatrixRoomTopic)
	case event.StateRoomAvatar:
		handleMatrixRoomMeta(portal, ctx, login, origSender, evt, RoomAvatarHandlingNetworkAPI.HandleMatrixRoomAvatar)
	case event.StateEncryption:
	}
}

func (portal *Portal) handleMatrixReceipts(evt *event.Event) {
	content, ok := evt.Content.Parsed.(*event.ReceiptEventContent)
	if !ok {
		return
	}
	for evtID, receipts := range *content {
		readReceipts, ok := receipts[event.ReceiptTypeRead]
		if !ok {
			continue
		}
		for userID, receipt := range readReceipts {
			sender, err := portal.Bridge.GetUserByMXID(context.TODO(), userID)
			if err != nil {
				// TODO log
				return
			}
			portal.handleMatrixReadReceipt(sender, evtID, receipt)
		}
	}
}

func (portal *Portal) handleMatrixReadReceipt(user *User, eventID id.EventID, receipt event.ReadReceipt) {
	log := portal.Log.With().
		Str("action", "handle matrix read receipt").
		Stringer("event_id", eventID).
		Stringer("user_id", user.MXID).
		Logger()
	ctx := log.WithContext(context.TODO())
	login, userPortal, err := portal.FindPreferredLogin(ctx, user, false)
	if err != nil {
		if !errors.Is(err, ErrNotLoggedIn) {
			log.Err(err).Msg("Failed to get preferred login for user")
		}
		return
	} else if login == nil {
		return
	}
	rrClient, ok := login.Client.(ReadReceiptHandlingNetworkAPI)
	if !ok {
		return
	}
	evt := &MatrixReadReceipt{
		Portal:  portal,
		EventID: eventID,
		Receipt: receipt,
	}
	if userPortal == nil {
		userPortal = database.UserPortalFor(login.UserLogin, portal.PortalKey)
	} else {
		userPortal = userPortal.CopyWithoutValues()
		evt.LastRead = userPortal.LastRead
	}
	evt.ExactMessage, err = portal.Bridge.DB.Message.GetPartByMXID(ctx, eventID)
	if err != nil {
		log.Err(err).Msg("Failed to get exact message from database")
	} else if evt.ExactMessage != nil {
		evt.ReadUpTo = evt.ExactMessage.Timestamp
	} else {
		evt.ReadUpTo = receipt.Timestamp
	}
	err = rrClient.HandleMatrixReadReceipt(ctx, evt)
	if err != nil {
		log.Err(err).Msg("Failed to handle read receipt")
		return
	}
	if evt.ExactMessage != nil {
		userPortal.LastRead = evt.ExactMessage.Timestamp
	} else {
		userPortal.LastRead = receipt.Timestamp
	}
	err = portal.Bridge.DB.UserPortal.Put(ctx, userPortal)
	if err != nil {
		log.Err(err).Msg("Failed to save user portal metadata")
	}
	portal.Bridge.DisappearLoop.StartAll(ctx, portal.MXID)
}

func (portal *Portal) handleMatrixTyping(evt *event.Event) {
	content, ok := evt.Content.Parsed.(*event.TypingEventContent)
	if !ok {
		return
	}
	portal.currentlyTypingLock.Lock()
	defer portal.currentlyTypingLock.Unlock()
	slices.Sort(content.UserIDs)
	stoppedTyping, startedTyping := exslices.SortedDiff(portal.currentlyTyping, content.UserIDs, func(a, b id.UserID) int {
		return strings.Compare(string(a), string(b))
	})
	ctx := portal.Log.WithContext(context.TODO())
	portal.sendTypings(ctx, stoppedTyping, false)
	portal.sendTypings(ctx, startedTyping, true)
	portal.currentlyTyping = content.UserIDs
}

func (portal *Portal) sendTypings(ctx context.Context, userIDs []id.UserID, typing bool) {
	for _, userID := range userIDs {
		login, ok := portal.currentlyTypingLogins[userID]
		if !ok && !typing {
			continue
		} else if !ok {
			user, err := portal.Bridge.GetUserByMXID(ctx, userID)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Stringer("user_id", userID).Msg("Failed to get user to send typing event")
				continue
			} else if user == nil {
				continue
			}
			login, _, err = portal.FindPreferredLogin(ctx, user, false)
			if err != nil {
				if !errors.Is(err, ErrNotLoggedIn) {
					zerolog.Ctx(ctx).Err(err).Stringer("user_id", userID).Msg("Failed to get user login to send typing event")
				}
				continue
			} else if login == nil {
				continue
			} else if _, ok = login.Client.(TypingHandlingNetworkAPI); !ok {
				continue
			}
			portal.currentlyTypingLogins[userID] = login
		}
		if !typing {
			delete(portal.currentlyTypingLogins, userID)
		}
		typingAPI, ok := login.Client.(TypingHandlingNetworkAPI)
		if !ok {
			continue
		}
		err := typingAPI.HandleMatrixTyping(ctx, &MatrixTyping{
			Portal:   portal,
			IsTyping: typing,
			Type:     TypingTypeText,
		})
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Stringer("user_id", userID).Msg("Failed to bridge Matrix typing event")
		} else {
			zerolog.Ctx(ctx).Debug().
				Stringer("user_id", userID).
				Bool("typing", typing).
				Msg("Sent typing event")
		}
	}
}

func (portal *Portal) periodicTypingUpdater() {
	// TODO actually call this function
	log := portal.Log.With().Str("component", "typing updater").Logger()
	ctx := log.WithContext(context.Background())
	for {
		// TODO make delay configurable by network connector
		time.Sleep(5 * time.Second)
		portal.currentlyTypingLock.Lock()
		if len(portal.currentlyTyping) == 0 {
			portal.currentlyTypingLock.Unlock()
			continue
		}
		for _, userID := range portal.currentlyTyping {
			login, ok := portal.currentlyTypingLogins[userID]
			if !ok {
				continue
			}
			typingAPI, ok := login.Client.(TypingHandlingNetworkAPI)
			if !ok {
				continue
			}
			err := typingAPI.HandleMatrixTyping(ctx, &MatrixTyping{
				Portal:   portal,
				IsTyping: true,
				Type:     TypingTypeText,
			})
			if err != nil {
				log.Err(err).Stringer("user_id", userID).Msg("Failed to repeat Matrix typing event")
			} else {
				log.Debug().
					Stringer("user_id", userID).
					Bool("typing", true).
					Msg("Sent repeated typing event")
			}
		}
		portal.currentlyTypingLock.Unlock()
	}
}

func (portal *Portal) checkMessageContentCaps(ctx context.Context, caps *NetworkRoomCapabilities, content *event.MessageEventContent, evt *event.Event) bool {
	switch content.MsgType {
	case event.MsgText, event.MsgNotice, event.MsgEmote:
		// No checks for now, message length is safer to check after conversion inside connector
	case event.MsgLocation:
		if !caps.LocationMessages {
			portal.sendErrorStatus(ctx, evt, ErrLocationMessagesNotAllowed)
			return false
		}
	case event.MsgImage, event.MsgAudio, event.MsgVideo, event.MsgFile:
		if content.FileName != "" && content.Body != content.FileName {
			if !caps.Captions {
				portal.sendErrorStatus(ctx, evt, ErrCaptionsNotAllowed)
				return false
			}
		}
	default:
	}
	return true
}

func (portal *Portal) handleMatrixMessage(ctx context.Context, sender *UserLogin, origSender *OrigSender, evt *event.Event) {
	log := zerolog.Ctx(ctx)
	content, ok := evt.Content.Parsed.(*event.MessageEventContent)
	if !ok {
		log.Error().Type("content_type", evt.Content.Parsed).Msg("Unexpected parsed content type")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: %T", ErrUnexpectedParsedContentType, evt.Content.Parsed))
		return
	}
	caps := sender.Client.GetCapabilities(ctx, portal)

	if content.RelatesTo.GetReplaceID() != "" {
		portal.handleMatrixEdit(ctx, sender, origSender, evt, content, caps)
		return
	}
	var err error
	if origSender != nil {
		content, err = portal.Bridge.Config.Relay.FormatMessage(content, origSender)
		if err != nil {
			log.Err(err).Msg("Failed to format message for relaying")
			portal.sendErrorStatus(ctx, evt, err)
			return
		}
	}
	if !portal.checkMessageContentCaps(ctx, caps, content, evt) {
		return
	}

	var threadRoot, replyTo *database.Message
	if caps.Threads {
		threadRootID := content.RelatesTo.GetThreadParent()
		if threadRootID != "" {
			threadRoot, err = portal.Bridge.DB.Message.GetPartByMXID(ctx, threadRootID)
			if err != nil {
				log.Err(err).Msg("Failed to get thread root message from database")
			}
		}
	}
	if caps.Replies {
		var replyToID id.EventID
		if caps.Threads {
			replyToID = content.RelatesTo.GetNonFallbackReplyTo()
		} else {
			replyToID = content.RelatesTo.GetReplyTo()
		}
		if replyToID != "" {
			replyTo, err = portal.Bridge.DB.Message.GetPartByMXID(ctx, replyToID)
			if err != nil {
				log.Err(err).Msg("Failed to get reply target message from database")
			}
		}
	}

	resp, err := sender.Client.HandleMatrixMessage(ctx, &MatrixMessage{
		MatrixEventBase: MatrixEventBase[*event.MessageEventContent]{
			Event:      evt,
			Content:    content,
			OrigSender: origSender,
			Portal:     portal,
		},
		ThreadRoot: threadRoot,
		ReplyTo:    replyTo,
	})
	if err != nil {
		log.Err(err).Msg("Failed to handle Matrix message")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}
	message := resp.DB
	if message.MXID == "" {
		message.MXID = evt.ID
	}
	if message.Room.ID == "" {
		message.Room = portal.PortalKey
	}
	if message.Timestamp.IsZero() {
		message.Timestamp = time.UnixMilli(evt.Timestamp)
	}
	message.Metadata.SenderMXID = evt.Sender
	// Hack to ensure the ghost row exists
	// TODO move to better place (like login)
	portal.Bridge.GetGhostByID(ctx, message.SenderID)
	err = portal.Bridge.DB.Message.Insert(ctx, message)
	if err != nil {
		log.Err(err).Msg("Failed to save message to database")
	}
	if portal.Metadata.DisappearType != database.DisappearingTypeNone {
		go portal.Bridge.DisappearLoop.Add(ctx, &database.DisappearingMessage{
			RoomID:  portal.MXID,
			EventID: message.MXID,
			DisappearingSetting: database.DisappearingSetting{
				Type:        portal.Metadata.DisappearType,
				Timer:       portal.Metadata.DisappearTimer,
				DisappearAt: message.Timestamp.Add(portal.Metadata.DisappearTimer),
			},
		})
	}
	portal.sendSuccessStatus(ctx, evt)
}

func (portal *Portal) handleMatrixEdit(ctx context.Context, sender *UserLogin, origSender *OrigSender, evt *event.Event, content *event.MessageEventContent, caps *NetworkRoomCapabilities) {
	log := zerolog.Ctx(ctx)
	editTargetID := content.RelatesTo.GetReplaceID()
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Stringer("edit_target_mxid", editTargetID)
	})
	if content.NewContent != nil {
		content = content.NewContent
	}
	if origSender != nil {
		var err error
		content, err = portal.Bridge.Config.Relay.FormatMessage(content, origSender)
		if err != nil {
			log.Err(err).Msg("Failed to format message for relaying")
			portal.sendErrorStatus(ctx, evt, err)
			return
		}
	}

	editingAPI, ok := sender.Client.(EditHandlingNetworkAPI)
	if !ok {
		log.Debug().Msg("Ignoring edit as network connector doesn't implement EditHandlingNetworkAPI")
		portal.sendErrorStatus(ctx, evt, ErrEditsNotSupported)
		return
	} else if !caps.Edits {
		log.Debug().Msg("Ignoring edit as room doesn't support edits")
		portal.sendErrorStatus(ctx, evt, ErrEditsNotSupportedInPortal)
		return
	} else if !portal.checkMessageContentCaps(ctx, caps, content, evt) {
		return
	}
	editTarget, err := portal.Bridge.DB.Message.GetPartByMXID(ctx, editTargetID)
	if err != nil {
		log.Err(err).Msg("Failed to get edit target message from database")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: failed to get edit target: %w", ErrDatabaseError, err))
		return
	} else if editTarget == nil {
		log.Warn().Msg("Edit target message not found in database")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("edit %w", ErrTargetMessageNotFound))
		return
	} else if caps.EditMaxAge > 0 && time.Since(editTarget.Timestamp) > caps.EditMaxAge {
		portal.sendErrorStatus(ctx, evt, ErrEditTargetTooOld)
		return
	} else if caps.EditMaxCount > 0 && editTarget.Metadata.EditCount >= caps.EditMaxCount {
		portal.sendErrorStatus(ctx, evt, ErrEditTargetTooManyEdits)
		return
	}
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("edit_target_remote_id", string(editTarget.ID))
	})
	err = editingAPI.HandleMatrixEdit(ctx, &MatrixEdit{
		MatrixEventBase: MatrixEventBase[*event.MessageEventContent]{
			Event:      evt,
			Content:    content,
			OrigSender: origSender,
			Portal:     portal,
		},
		EditTarget: editTarget,
	})
	if err != nil {
		log.Err(err).Msg("Failed to handle Matrix edit")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}
	err = portal.Bridge.DB.Message.Update(ctx, editTarget)
	if err != nil {
		log.Err(err).Msg("Failed to save message to database after editing")
	}
	portal.sendSuccessStatus(ctx, evt)
}

func (portal *Portal) handleMatrixReaction(ctx context.Context, sender *UserLogin, evt *event.Event) {
	log := zerolog.Ctx(ctx)
	reactingAPI, ok := sender.Client.(ReactionHandlingNetworkAPI)
	if !ok {
		log.Debug().Msg("Ignoring reaction as network connector doesn't implement ReactionHandlingNetworkAPI")
		portal.sendErrorStatus(ctx, evt, ErrReactionsNotSupported)
		return
	}
	content, ok := evt.Content.Parsed.(*event.ReactionEventContent)
	if !ok {
		log.Error().Type("content_type", evt.Content.Parsed).Msg("Unexpected parsed content type")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: %T", ErrUnexpectedParsedContentType, evt.Content.Parsed))
		return
	}
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Stringer("reaction_target_mxid", content.RelatesTo.EventID)
	})
	reactionTarget, err := portal.Bridge.DB.Message.GetPartByMXID(ctx, content.RelatesTo.EventID)
	if err != nil {
		log.Err(err).Msg("Failed to get reaction target message from database")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: failed to get reaction target: %w", ErrDatabaseError, err))
		return
	} else if reactionTarget == nil {
		log.Warn().Msg("Reaction target message not found in database")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("reaction %w", ErrTargetMessageNotFound))
		return
	}
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("reaction_target_remote_id", string(reactionTarget.ID))
	})
	react := &MatrixReaction{
		MatrixEventBase: MatrixEventBase[*event.ReactionEventContent]{
			Event:   evt,
			Content: content,
			Portal:  portal,
		},
		TargetMessage: reactionTarget,
	}
	preResp, err := reactingAPI.PreHandleMatrixReaction(ctx, react)
	if err != nil {
		log.Err(err).Msg("Failed to pre-handle Matrix reaction")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}
	existing, err := portal.Bridge.DB.Reaction.GetByID(ctx, reactionTarget.ID, reactionTarget.PartID, preResp.SenderID, preResp.EmojiID)
	if err != nil {
		log.Err(err).Msg("Failed to check if reaction is a duplicate")
		return
	} else if existing != nil {
		if existing.EmojiID != "" || existing.Metadata.Emoji == preResp.Emoji {
			log.Debug().Msg("Ignoring duplicate reaction")
			portal.sendSuccessStatus(ctx, evt)
			return
		}
		_, err = portal.Bridge.Bot.SendMessage(ctx, portal.MXID, event.EventRedaction, &event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: existing.MXID,
			},
		}, time.Now())
		if err != nil {
			log.Err(err).Msg("Failed to remove old reaction")
		}
	}
	react.PreHandleResp = &preResp
	if preResp.MaxReactions > 0 {
		allReactions, err := portal.Bridge.DB.Reaction.GetAllToMessageBySender(ctx, reactionTarget.ID, preResp.SenderID)
		if err != nil {
			log.Err(err).Msg("Failed to get all reactions to message by sender")
			portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: failed to get previous reactions: %w", ErrDatabaseError, err))
			return
		}
		if len(allReactions) < preResp.MaxReactions {
			react.ExistingReactionsToKeep = allReactions
		} else {
			// Keep n-1 previous reactions and remove the rest
			react.ExistingReactionsToKeep = allReactions[:preResp.MaxReactions-1]
			for _, oldReaction := range allReactions[preResp.MaxReactions-1:] {
				_, err = portal.Bridge.Bot.SendMessage(ctx, portal.MXID, event.EventRedaction, &event.Content{
					Parsed: &event.RedactionEventContent{
						Redacts: oldReaction.MXID,
					},
				}, time.Now())
				if err != nil {
					log.Err(err).Msg("Failed to remove previous reaction after limit was exceeded")
				}
				err = portal.Bridge.DB.Reaction.Delete(ctx, oldReaction)
				if err != nil {
					log.Err(err).Msg("Failed to delete previous reaction from database after limit was exceeded")
				}
			}
		}
	}
	dbReaction, err := reactingAPI.HandleMatrixReaction(ctx, react)
	if err != nil {
		log.Err(err).Msg("Failed to handle Matrix reaction")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}
	// Fill all fields that are known to allow omitting them in connector code
	if dbReaction.Room.ID == "" {
		dbReaction.Room = portal.PortalKey
	}
	if dbReaction.MessageID == "" {
		dbReaction.MessageID = reactionTarget.ID
		dbReaction.MessagePartID = reactionTarget.PartID
	}
	if dbReaction.MXID == "" {
		dbReaction.MXID = evt.ID
	}
	if dbReaction.Timestamp.IsZero() {
		dbReaction.Timestamp = time.UnixMilli(evt.Timestamp)
	}
	if preResp.EmojiID == "" && dbReaction.EmojiID == "" {
		if dbReaction.Metadata.Emoji == "" {
			dbReaction.Metadata.Emoji = preResp.Emoji
		}
	} else if dbReaction.EmojiID == "" {
		dbReaction.EmojiID = preResp.EmojiID
	}
	if dbReaction.SenderID == "" {
		dbReaction.SenderID = preResp.SenderID
	}
	err = portal.Bridge.DB.Reaction.Upsert(ctx, dbReaction)
	if err != nil {
		log.Err(err).Msg("Failed to save reaction to database")
	}
	portal.sendSuccessStatus(ctx, evt)
}

func handleMatrixRoomMeta[APIType any, ContentType RoomMetaEventContent](
	portal *Portal,
	ctx context.Context,
	sender *UserLogin,
	origSender *OrigSender,
	evt *event.Event,
	fn func(APIType, context.Context, *MatrixRoomMeta[ContentType]) (bool, error),
) {
	api, ok := sender.Client.(APIType)
	if !ok {
		portal.sendErrorStatus(ctx, evt, ErrRoomMetadataNotSupported)
		return
	}
	log := zerolog.Ctx(ctx)
	content, ok := evt.Content.Parsed.(ContentType)
	if !ok {
		log.Error().Type("content_type", evt.Content.Parsed).Msg("Unexpected parsed content type")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: %T", ErrUnexpectedParsedContentType, evt.Content.Parsed))
		return
	}
	switch typedContent := evt.Content.Parsed.(type) {
	case *event.RoomNameEventContent:
		if typedContent.Name == portal.Name {
			portal.sendSuccessStatus(ctx, evt)
			return
		}
	case *event.TopicEventContent:
		if typedContent.Topic == portal.Topic {
			portal.sendSuccessStatus(ctx, evt)
			return
		}
	case *event.RoomAvatarEventContent:
		if typedContent.URL == portal.AvatarMXC {
			portal.sendSuccessStatus(ctx, evt)
			return
		}
	}
	var prevContent ContentType
	if evt.Unsigned.PrevContent != nil {
		_ = evt.Unsigned.PrevContent.ParseRaw(evt.Type)
		prevContent, _ = evt.Unsigned.PrevContent.Parsed.(ContentType)
	}

	changed, err := fn(api, ctx, &MatrixRoomMeta[ContentType]{
		MatrixEventBase: MatrixEventBase[ContentType]{
			Event:      evt,
			Content:    content,
			Portal:     portal,
			OrigSender: origSender,
		},
		PrevContent: prevContent,
	})
	if err != nil {
		log.Err(err).Msg("Failed to handle Matrix room metadata")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}
	if changed {
		portal.UpdateBridgeInfo(ctx)
		err = portal.Save(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to save portal after updating room metadata")
		}
	}
	portal.sendSuccessStatus(ctx, evt)
}

func (portal *Portal) handleMatrixRedaction(ctx context.Context, sender *UserLogin, origSender *OrigSender, evt *event.Event) {
	log := zerolog.Ctx(ctx)
	content, ok := evt.Content.Parsed.(*event.RedactionEventContent)
	if !ok {
		log.Error().Type("content_type", evt.Content.Parsed).Msg("Unexpected parsed content type")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: %T", ErrUnexpectedParsedContentType, evt.Content.Parsed))
		return
	}
	if evt.Redacts != "" && content.Redacts != evt.Redacts {
		content.Redacts = evt.Redacts
	}
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Stringer("redaction_target_mxid", content.Redacts)
	})
	deletingAPI, deleteOK := sender.Client.(RedactionHandlingNetworkAPI)
	reactingAPI, reactOK := sender.Client.(ReactionHandlingNetworkAPI)
	if !deleteOK && !reactOK {
		log.Debug().Msg("Ignoring redaction without checking target as network connector doesn't implement RedactionHandlingNetworkAPI nor ReactionHandlingNetworkAPI")
		portal.sendErrorStatus(ctx, evt, ErrRedactionsNotSupported)
		return
	}
	var redactionTargetReaction *database.Reaction
	redactionTargetMsg, err := portal.Bridge.DB.Message.GetPartByMXID(ctx, content.Redacts)
	if err != nil {
		log.Err(err).Msg("Failed to get redaction target message from database")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: failed to get redaction target message: %w", ErrDatabaseError, err))
		return
	} else if redactionTargetMsg != nil {
		if !deleteOK {
			log.Debug().Msg("Ignoring message redaction event as network connector doesn't implement RedactionHandlingNetworkAPI")
			portal.sendErrorStatus(ctx, evt, ErrRedactionsNotSupported)
			return
		}
		err = deletingAPI.HandleMatrixMessageRemove(ctx, &MatrixMessageRemove{
			MatrixEventBase: MatrixEventBase[*event.RedactionEventContent]{
				Event:      evt,
				Content:    content,
				Portal:     portal,
				OrigSender: origSender,
			},
			TargetMessage: redactionTargetMsg,
		})
	} else if redactionTargetReaction, err = portal.Bridge.DB.Reaction.GetByMXID(ctx, content.Redacts); err != nil {
		log.Err(err).Msg("Failed to get redaction target reaction from database")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: failed to get redaction target message reaction: %w", ErrDatabaseError, err))
		return
	} else if redactionTargetReaction != nil {
		if !reactOK {
			log.Debug().Msg("Ignoring reaction redaction event as network connector doesn't implement ReactionHandlingNetworkAPI")
			portal.sendErrorStatus(ctx, evt, ErrReactionsNotSupported)
			return
		}
		// TODO ignore if sender doesn't match?
		err = reactingAPI.HandleMatrixReactionRemove(ctx, &MatrixReactionRemove{
			MatrixEventBase: MatrixEventBase[*event.RedactionEventContent]{
				Event:      evt,
				Content:    content,
				Portal:     portal,
				OrigSender: origSender,
			},
			TargetReaction: redactionTargetReaction,
		})
	} else {
		log.Debug().Msg("Redaction target message not found in database")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("redaction %w", ErrTargetMessageNotFound))
		return
	}
	if err != nil {
		log.Err(err).Msg("Failed to handle Matrix redaction")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}
	// TODO delete msg/reaction db row
	portal.sendSuccessStatus(ctx, evt)
}

func (portal *Portal) handleRemoteEvent(source *UserLogin, evt RemoteEvent) {
	log := portal.Log.With().
		Str("source_id", string(source.ID)).
		Str("action", "handle remote event").
		Logger()
	log.UpdateContext(evt.AddLogContext)
	ctx := log.WithContext(context.TODO())
	if portal.MXID == "" {
		mcp, ok := evt.(RemoteEventThatMayCreatePortal)
		if !ok || !mcp.ShouldCreatePortal() {
			return
		}
		err := portal.CreateMatrixRoom(ctx, source, nil)
		if err != nil {
			log.Err(err).Msg("Failed to create portal to handle event")
			// TODO error
			return
		}
	}
	preHandler, ok := evt.(RemotePreHandler)
	if ok {
		preHandler.PreHandle(ctx, portal)
	}
	switch evt.GetType() {
	case RemoteEventUnknown:
		log.Debug().Msg("Ignoring remote event with type unknown")
	case RemoteEventMessage:
		portal.handleRemoteMessage(ctx, source, evt.(RemoteMessage))
	case RemoteEventEdit:
		portal.handleRemoteEdit(ctx, source, evt.(RemoteEdit))
	case RemoteEventReaction:
		portal.handleRemoteReaction(ctx, source, evt.(RemoteReaction))
	case RemoteEventReactionRemove:
		portal.handleRemoteReactionRemove(ctx, source, evt.(RemoteReactionRemove))
	case RemoteEventMessageRemove:
		portal.handleRemoteMessageRemove(ctx, source, evt.(RemoteMessageRemove))
	case RemoteEventReadReceipt:
		portal.handleRemoteReadReceipt(ctx, source, evt.(RemoteReceipt))
	case RemoteEventMarkUnread:
		portal.handleRemoteMarkUnread(ctx, source, evt.(RemoteMarkUnread))
	case RemoteEventDeliveryReceipt:
		portal.handleRemoteDeliveryReceipt(ctx, source, evt.(RemoteReceipt))
	case RemoteEventTyping:
		portal.handleRemoteTyping(ctx, source, evt.(RemoteTyping))
	case RemoteEventChatInfoChange:
		portal.handleRemoteChatInfoChange(ctx, source, evt.(RemoteChatInfoChange))
	default:
		log.Warn().Int("type", int(evt.GetType())).Msg("Got remote event with unknown type")
	}
}

func (portal *Portal) getIntentAndUserMXIDFor(ctx context.Context, sender EventSender, source *UserLogin, otherLogins []*UserLogin, evtType RemoteEventType) (intent MatrixAPI, extraUserID id.UserID) {
	if sender.IsFromMe {
		intent = source.User.DoublePuppet(ctx)
		if intent != nil {
			return
		}
		extraUserID = source.UserMXID
	} else if sender.SenderLogin != "" && portal.Receiver == "" {
		senderLogin := portal.Bridge.GetCachedUserLoginByID(sender.SenderLogin)
		if senderLogin != nil {
			intent = senderLogin.User.DoublePuppet(ctx)
			if intent != nil {
				return
			}
			extraUserID = senderLogin.UserMXID
		}
	}
	if sender.Sender != "" {
		if portal.Receiver == "" {
			for _, login := range otherLogins {
				if login.Client.IsThisUser(ctx, sender.Sender) {
					intent = login.User.DoublePuppet(ctx)
					if intent != nil {
						return
					}
					extraUserID = login.UserMXID
				}
			}
		}
		ghost, err := portal.Bridge.GetGhostByID(ctx, sender.Sender)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get ghost for message sender")
			return
		} else {
			ghost.UpdateInfoIfNecessary(ctx, source, evtType)
			intent = ghost.Intent
		}
	}
	return
}

func (portal *Portal) GetIntentFor(ctx context.Context, sender EventSender, source *UserLogin, evtType RemoteEventType) MatrixAPI {
	intent, _ := portal.getIntentAndUserMXIDFor(ctx, sender, source, nil, evtType)
	if intent == nil {
		intent = portal.Bridge.Bot
	}
	return intent
}

func (portal *Portal) handleRemoteMessage(ctx context.Context, source *UserLogin, evt RemoteMessage) {
	log := zerolog.Ctx(ctx)
	existing, err := portal.Bridge.DB.Message.GetFirstPartByID(ctx, portal.Receiver, evt.GetID())
	if err != nil {
		log.Err(err).Msg("Failed to check if message is a duplicate")
	} else if existing != nil {
		log.Debug().Stringer("existing_mxid", existing.MXID).Msg("Ignoring duplicate message")
		return
	}
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventMessage)
	if intent == nil {
		return
	}
	ts := getEventTS(evt)
	converted, err := evt.ConvertMessage(ctx, portal, intent)
	if err != nil {
		log.Err(err).Msg("Failed to convert remote message")
		portal.sendRemoteErrorNotice(ctx, intent, err, ts, "message")
		return
	}
	var relatesToRowID int64
	var replyTo, threadRoot, prevThreadEvent *database.Message
	if converted.ReplyTo != nil {
		replyTo, err = portal.Bridge.DB.Message.GetFirstOrSpecificPartByID(ctx, portal.Receiver, *converted.ReplyTo)
		if err != nil {
			log.Err(err).Msg("Failed to get reply target message from database")
		} else if replyTo == nil {
			log.Warn().Any("reply_to", converted.ReplyTo).Msg("Reply target message not found in database")
		} else {
			relatesToRowID = replyTo.RowID
		}
	}
	if converted.ThreadRoot != nil {
		threadRoot, err = portal.Bridge.DB.Message.GetFirstOrSpecificPartByID(ctx, portal.Receiver, *converted.ThreadRoot)
		if err != nil {
			log.Err(err).Msg("Failed to get thread root message from database")
		} else if threadRoot == nil {
			log.Warn().Any("thread_root", converted.ThreadRoot).Msg("Thread root message not found in database")
		} else {
			relatesToRowID = threadRoot.RowID
		}
		// TODO thread roots need to be saved in the database in a way that allows fetching
		//      the first bridged thread message even if the original one isn't bridged

		// TODO 2 fetch last event in thread properly
		prevThreadEvent = threadRoot
	}
	for _, part := range converted.Parts {
		if threadRoot != nil && prevThreadEvent != nil {
			part.Content.GetRelatesTo().SetThread(threadRoot.MXID, prevThreadEvent.MXID)
		}
		if replyTo != nil {
			part.Content.GetRelatesTo().SetReplyTo(replyTo.MXID)
			if part.Content.Mentions == nil {
				part.Content.Mentions = &event.Mentions{}
			}
			if !slices.Contains(part.Content.Mentions.UserIDs, replyTo.Metadata.SenderMXID) {
				part.Content.Mentions.UserIDs = append(part.Content.Mentions.UserIDs, replyTo.Metadata.SenderMXID)
			}
		}
		resp, err := intent.SendMessage(ctx, portal.MXID, part.Type, &event.Content{
			Parsed: part.Content,
			Raw:    part.Extra,
		}, ts)
		if err != nil {
			log.Err(err).Str("part_id", string(part.ID)).Msg("Failed to send message part to Matrix")
			continue
		}
		log.Debug().
			Stringer("event_id", resp.EventID).
			Str("part_id", string(part.ID)).
			Msg("Sent message part to Matrix")
		dbMessage := &database.Message{
			ID:             evt.GetID(),
			PartID:         part.ID,
			MXID:           resp.EventID,
			Room:           portal.PortalKey,
			SenderID:       evt.GetSender().Sender,
			Timestamp:      ts,
			RelatesToRowID: relatesToRowID,
		}
		dbMessage.Metadata.SenderMXID = intent.GetMXID()
		dbMessage.Metadata.Extra = part.DBMetadata
		err = portal.Bridge.DB.Message.Insert(ctx, dbMessage)
		if err != nil {
			log.Err(err).Str("part_id", string(part.ID)).Msg("Failed to save message part to database")
		}
		if converted.Disappear.Type != database.DisappearingTypeNone {
			if converted.Disappear.Type == database.DisappearingTypeAfterSend && converted.Disappear.DisappearAt.IsZero() {
				converted.Disappear.DisappearAt = dbMessage.Timestamp.Add(converted.Disappear.Timer)
			}
			go portal.Bridge.DisappearLoop.Add(ctx, &database.DisappearingMessage{
				RoomID:              portal.MXID,
				EventID:             dbMessage.MXID,
				DisappearingSetting: converted.Disappear,
			})
		}
		if prevThreadEvent != nil {
			prevThreadEvent = dbMessage
		}
	}
}

func (portal *Portal) sendRemoteErrorNotice(ctx context.Context, intent MatrixAPI, err error, ts time.Time, evtTypeName string) {
	resp, sendErr := intent.SendMessage(ctx, portal.MXID, event.EventMessage, &event.Content{
		Parsed: &event.MessageEventContent{
			MsgType:  event.MsgNotice,
			Body:     fmt.Sprintf("An error occurred while processing an incoming %s", evtTypeName),
			Mentions: &event.Mentions{},
		},
		Raw: map[string]any{
			"fi.mau.bridge.internal_error": err.Error(),
		},
	}, ts)
	if sendErr != nil {
		zerolog.Ctx(ctx).Err(sendErr).Msg("Failed to send error notice after remote event handling failed")
	} else {
		zerolog.Ctx(ctx).Debug().Stringer("event_id", resp.EventID).Msg("Sent error notice after remote event handling failed")
	}
}

func (portal *Portal) handleRemoteEdit(ctx context.Context, source *UserLogin, evt RemoteEdit) {
	log := zerolog.Ctx(ctx)
	existing, err := portal.Bridge.DB.Message.GetAllPartsByID(ctx, portal.Receiver, evt.GetTargetMessage())
	if err != nil {
		log.Err(err).Msg("Failed to get edit target message")
		return
	} else if existing == nil {
		log.Warn().Msg("Edit target message not found")
		return
	}
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventEdit)
	if intent == nil {
		return
	}
	ts := getEventTS(evt)
	converted, err := evt.ConvertEdit(ctx, portal, intent, existing)
	if err != nil {
		log.Err(err).Msg("Failed to convert remote edit")
		portal.sendRemoteErrorNotice(ctx, intent, err, ts, "edit")
		return
	}
	for _, part := range converted.ModifiedParts {
		part.Content.SetEdit(part.Part.MXID)
		if part.TopLevelExtra == nil {
			part.TopLevelExtra = make(map[string]any)
		}
		if part.Extra != nil {
			part.TopLevelExtra["m.new_content"] = part.Extra
		}
		wrappedContent := &event.Content{
			Parsed: part.Content,
			Raw:    part.TopLevelExtra,
		}
		resp, err := intent.SendMessage(ctx, portal.MXID, part.Type, wrappedContent, ts)
		if err != nil {
			log.Err(err).Stringer("part_mxid", part.Part.MXID).Msg("Failed to edit message part")
		} else {
			log.Debug().
				Stringer("event_id", resp.EventID).
				Str("part_id", string(part.Part.ID)).
				Msg("Sent message part edit to Matrix")
		}
		err = portal.Bridge.DB.Message.Update(ctx, part.Part)
		if err != nil {
			log.Err(err).Int64("part_rowid", part.Part.RowID).Msg("Failed to update message part in database")
		}
	}
	for _, part := range converted.DeletedParts {
		redactContent := &event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: part.MXID,
			},
		}
		resp, err := intent.SendMessage(ctx, portal.MXID, event.EventRedaction, redactContent, ts)
		if err != nil {
			log.Err(err).Stringer("part_mxid", part.MXID).Msg("Failed to redact message part deleted in edit")
		} else {
			log.Debug().
				Stringer("redaction_event_id", resp.EventID).
				Stringer("redacted_event_id", part.MXID).
				Str("part_id", string(part.ID)).
				Msg("Sent redaction of message part to Matrix")
		}
		err = portal.Bridge.DB.Message.Delete(ctx, part.RowID)
		if err != nil {
			log.Err(err).Int64("part_rowid", part.RowID).Msg("Failed to delete message part from database")
		}
	}
}

func (portal *Portal) getTargetMessagePart(ctx context.Context, evt RemoteEventWithTargetMessage) (*database.Message, error) {
	if partTargeter, ok := evt.(RemoteEventWithTargetPart); ok {
		return portal.Bridge.DB.Message.GetPartByID(ctx, portal.Receiver, evt.GetTargetMessage(), partTargeter.GetTargetMessagePart())
	} else {
		return portal.Bridge.DB.Message.GetFirstPartByID(ctx, portal.Receiver, evt.GetTargetMessage())
	}
}

func (portal *Portal) getTargetReaction(ctx context.Context, evt RemoteReactionRemove) (*database.Reaction, error) {
	if partTargeter, ok := evt.(RemoteEventWithTargetPart); ok {
		return portal.Bridge.DB.Reaction.GetByID(ctx, evt.GetTargetMessage(), partTargeter.GetTargetMessagePart(), evt.GetSender().Sender, evt.GetRemovedEmojiID())
	} else {
		return portal.Bridge.DB.Reaction.GetByIDWithoutMessagePart(ctx, evt.GetTargetMessage(), evt.GetSender().Sender, evt.GetRemovedEmojiID())
	}
}

func getEventTS(evt RemoteEvent) time.Time {
	if tsProvider, ok := evt.(RemoteEventWithTimestamp); ok {
		return tsProvider.GetTimestamp()
	}
	return time.Now()
}

func (portal *Portal) handleRemoteReaction(ctx context.Context, source *UserLogin, evt RemoteReaction) {
	log := zerolog.Ctx(ctx)
	targetMessage, err := portal.getTargetMessagePart(ctx, evt)
	if err != nil {
		log.Err(err).Msg("Failed to get target message for reaction")
		return
	}
	emoji, emojiID := evt.GetReactionEmoji()
	existingReaction, err := portal.Bridge.DB.Reaction.GetByID(ctx, targetMessage.ID, targetMessage.PartID, evt.GetSender().Sender, emojiID)
	if err != nil {
		log.Err(err).Msg("Failed to check if reaction is a duplicate")
		return
	} else if existingReaction != nil && (emojiID != "" || existingReaction.Metadata.Emoji == emoji) {
		log.Debug().Msg("Ignoring duplicate reaction")
		return
	}
	ts := getEventTS(evt)
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventReaction)
	resp, err := intent.SendMessage(ctx, portal.MXID, event.EventReaction, &event.Content{
		Parsed: &event.ReactionEventContent{
			RelatesTo: event.RelatesTo{
				Type:    event.RelAnnotation,
				EventID: targetMessage.MXID,
				Key:     variationselector.Add(emoji),
			},
		},
	}, ts)
	if err != nil {
		log.Err(err).Msg("Failed to send reaction to Matrix")
		return
	}
	log.Debug().
		Stringer("event_id", resp.EventID).
		Msg("Sent reaction to Matrix")
	dbReaction := &database.Reaction{
		Room:          portal.PortalKey,
		MessageID:     targetMessage.ID,
		MessagePartID: targetMessage.PartID,
		SenderID:      evt.GetSender().Sender,
		EmojiID:       emojiID,
		MXID:          resp.EventID,
		Timestamp:     ts,
	}
	if metaProvider, ok := evt.(RemoteReactionWithMeta); ok {
		dbReaction.Metadata.Extra = metaProvider.GetReactionDBMetadata()
	}
	if emojiID == "" {
		dbReaction.Metadata.Emoji = emoji
	}
	err = portal.Bridge.DB.Reaction.Upsert(ctx, dbReaction)
	if err != nil {
		log.Err(err).Msg("Failed to save reaction to database")
	}
	if existingReaction != nil {
		_, err = intent.SendMessage(ctx, portal.MXID, event.EventRedaction, &event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: existingReaction.MXID,
			},
		}, ts)
		if err != nil {
			log.Err(err).Msg("Failed to redact old reaction")
		}
	}
}

func (portal *Portal) handleRemoteReactionRemove(ctx context.Context, source *UserLogin, evt RemoteReactionRemove) {
	log := zerolog.Ctx(ctx)
	targetReaction, err := portal.getTargetReaction(ctx, evt)
	if err != nil {
		log.Err(err).Msg("Failed to get target reaction for removal")
		return
	} else if targetReaction == nil {
		log.Warn().Msg("Target reaction not found")
		return
	}
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventReactionRemove)
	ts := getEventTS(evt)
	_, err = intent.SendMessage(ctx, portal.MXID, event.EventRedaction, &event.Content{
		Parsed: &event.RedactionEventContent{
			Redacts: targetReaction.MXID,
		},
	}, ts)
	if err != nil {
		log.Err(err).Stringer("reaction_mxid", targetReaction.MXID).Msg("Failed to redact reaction")
	}
	err = portal.Bridge.DB.Reaction.Delete(ctx, targetReaction)
	if err != nil {
		log.Err(err).Msg("Failed to delete target reaction from database")
	}
}

func (portal *Portal) handleRemoteMessageRemove(ctx context.Context, source *UserLogin, evt RemoteMessageRemove) {
	log := zerolog.Ctx(ctx)
	targetParts, err := portal.Bridge.DB.Message.GetAllPartsByID(ctx, portal.Receiver, evt.GetTargetMessage())
	if err != nil {
		log.Err(err).Msg("Failed to get target message for removal")
		return
	}
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventMessageRemove)
	ts := getEventTS(evt)
	for _, part := range targetParts {
		resp, err := intent.SendMessage(ctx, portal.MXID, event.EventRedaction, &event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: part.MXID,
			},
		}, ts)
		if err != nil {
			log.Err(err).Stringer("part_mxid", part.MXID).Msg("Failed to redact message part")
		} else {
			log.Debug().
				Stringer("redaction_event_id", resp.EventID).
				Stringer("redacted_event_id", part.MXID).
				Str("part_id", string(part.ID)).
				Msg("Sent redaction of message part to Matrix")
		}
	}
	err = portal.Bridge.DB.Message.DeleteAllParts(ctx, portal.Receiver, evt.GetTargetMessage())
	if err != nil {
		log.Err(err).Msg("Failed to delete target message from database")
	}
}

func (portal *Portal) handleRemoteReadReceipt(ctx context.Context, source *UserLogin, evt RemoteReceipt) {
	log := zerolog.Ctx(ctx)
	var err error
	var lastTarget *database.Message
	if lastTargetID := evt.GetLastReceiptTarget(); lastTargetID != "" {
		lastTarget, err = portal.Bridge.DB.Message.GetLastPartByID(ctx, portal.Receiver, lastTargetID)
		if err != nil {
			log.Err(err).Str("last_target_id", string(lastTargetID)).
				Msg("Failed to get last target message for read receipt")
			return
		} else if lastTarget == nil {
			log.Debug().Str("last_target_id", string(lastTargetID)).
				Msg("Last target message not found")
		}
	}
	if lastTarget == nil {
		for _, targetID := range evt.GetReceiptTargets() {
			target, err := portal.Bridge.DB.Message.GetLastPartByID(ctx, portal.Receiver, targetID)
			if err != nil {
				log.Err(err).Str("target_id", string(targetID)).
					Msg("Failed to get target message for read receipt")
				return
			} else if target != nil && (lastTarget == nil || target.Timestamp.After(lastTarget.Timestamp)) {
				lastTarget = target
			}
		}
	}
	if lastTarget == nil {
		log.Warn().Msg("No target message found for read receipt")
		return
	}
	sender := evt.GetSender()
	intent := portal.GetIntentFor(ctx, sender, source, RemoteEventReadReceipt)
	err = intent.MarkRead(ctx, portal.MXID, lastTarget.MXID, getEventTS(evt))
	if err != nil {
		log.Err(err).Stringer("target_mxid", lastTarget.MXID).Msg("Failed to bridge read receipt")
	} else {
		log.Debug().Stringer("target_mxid", lastTarget.MXID).Msg("Bridged read receipt")
	}
	if sender.IsFromMe {
		portal.Bridge.DisappearLoop.StartAll(ctx, portal.MXID)
	}
}

func (portal *Portal) handleRemoteMarkUnread(ctx context.Context, source *UserLogin, evt RemoteMarkUnread) {
	if !evt.GetSender().IsFromMe {
		zerolog.Ctx(ctx).Warn().Msg("Ignoring mark unread event from non-self user")
		return
	}
	dp := source.User.DoublePuppet(ctx)
	if dp == nil {
		return
	}
	err := dp.MarkUnread(ctx, portal.MXID, evt.GetUnread())
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to bridge mark unread event")
	}
}

func (portal *Portal) handleRemoteDeliveryReceipt(ctx context.Context, source *UserLogin, evt RemoteReceipt) {

}

func (portal *Portal) handleRemoteTyping(ctx context.Context, source *UserLogin, evt RemoteTyping) {
	var typingType TypingType
	if typedEvt, ok := evt.(RemoteTypingWithType); ok {
		typingType = typedEvt.GetTypingType()
	}
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventTyping)
	err := intent.MarkTyping(ctx, portal.MXID, typingType, evt.GetTimeout())
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to bridge typing event")
	}
}

func (portal *Portal) handleRemoteChatInfoChange(ctx context.Context, source *UserLogin, evt RemoteChatInfoChange) {
	info, err := evt.GetChatInfoChange(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to get chat info change")
		return
	}
	portal.ProcessChatInfoChange(ctx, evt.GetSender(), source, info, getEventTS(evt))
}

type ChatInfoChange struct {
	// The chat info that changed. Any fields that did not change can be left as nil.
	ChatInfo *ChatInfo
	// A list of member changes.
	// This list should only include changes, not the whole member list.
	// To resync the whole list, use the field inside ChatInfo.
	MemberChanges *ChatMemberList
}

func (portal *Portal) ProcessChatInfoChange(ctx context.Context, sender EventSender, source *UserLogin, change *ChatInfoChange, ts time.Time) {
	intent := portal.GetIntentFor(ctx, sender, source, RemoteEventChatInfoChange)
	if change.ChatInfo != nil {
		portal.UpdateInfo(ctx, change.ChatInfo, source, intent, ts)
	}
	if change.MemberChanges != nil {
		err := portal.SyncParticipants(ctx, change.MemberChanges, source, intent, ts)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to sync room members")
		}
	}
}

// Deprecated: Renamed to ChatInfo
type PortalInfo = ChatInfo

type ChatMember struct {
	EventSender
	Membership event.Membership
	Nickname   string
	PowerLevel int

	PrevMembership event.Membership
}

type ChatMemberList struct {
	// Whether this is the full member list.
	// If true, any extra members not listed here will be removed from the portal.
	IsFull bool
	// Should the bridge call IsThisUser for every member in the list?
	// This should be used when SenderLogin can't be filled accurately.
	CheckAllLogins bool

	Members     []ChatMember
	PowerLevels *PowerLevelChanges
}

type PowerLevelChanges struct {
	Events        map[event.Type]int
	UsersDefault  *int
	EventsDefault *int
	StateDefault  *int
	Invite        *int
	Kick          *int
	Ban           *int
	Redact        *int

	Custom func(*event.PowerLevelsEventContent) bool
}

func (plc *PowerLevelChanges) Apply(content *event.PowerLevelsEventContent) (changed bool) {
	if plc == nil || content == nil {
		return
	}
	for evtType, level := range plc.Events {
		changed = content.EnsureEventLevel(evtType, level) || changed
	}
	if plc.UsersDefault != nil {
		changed = content.UsersDefault != *plc.UsersDefault
		content.UsersDefault = *plc.UsersDefault
	}
	if plc.EventsDefault != nil {
		changed = content.EventsDefault != *plc.EventsDefault
		content.EventsDefault = *plc.EventsDefault
	}
	if plc.StateDefault != nil {
		changed = content.StateDefault() != *plc.StateDefault
		content.StateDefaultPtr = plc.StateDefault
	}
	if plc.Invite != nil {
		changed = content.Invite() != *plc.Invite
		content.InvitePtr = plc.Invite
	}
	if plc.Kick != nil {
		changed = content.Kick() != *plc.Kick
		content.KickPtr = plc.Kick
	}
	if plc.Ban != nil {
		changed = content.Ban() != *plc.Ban
		content.BanPtr = plc.Ban
	}
	if plc.Redact != nil {
		changed = content.Redact() != *plc.Redact
		content.RedactPtr = plc.Redact
	}
	if plc.Custom != nil {
		changed = plc.Custom(content) || changed
	}
	return changed
}

type ChatInfo struct {
	Name   *string
	Topic  *string
	Avatar *Avatar

	Members  *ChatMemberList
	JoinRule *event.JoinRulesEventContent

	IsDirectChat *bool
	IsSpace      *bool
	Disappear    *database.DisappearingSetting

	UserLocal *UserLocalPortalInfo

	ExtraUpdates func(context.Context, *Portal) bool
}

var Unmuted = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

type UserLocalPortalInfo struct {
	MutedUntil *time.Time
	Tag        *event.RoomTag
}

func (portal *Portal) UpdateName(ctx context.Context, name string, sender MatrixAPI, ts time.Time) bool {
	if portal.Name == name && (portal.NameSet || portal.MXID == "") {
		return false
	}
	portal.Name = name
	portal.NameSet = portal.sendRoomMeta(ctx, sender, ts, event.StateRoomName, "", &event.RoomNameEventContent{Name: name})
	return true
}

func (portal *Portal) UpdateTopic(ctx context.Context, topic string, sender MatrixAPI, ts time.Time) bool {
	if portal.Topic == topic && (portal.TopicSet || portal.MXID == "") {
		return false
	}
	portal.Topic = topic
	portal.TopicSet = portal.sendRoomMeta(ctx, sender, ts, event.StateTopic, "", &event.TopicEventContent{Topic: topic})
	return true
}

func (portal *Portal) UpdateAvatar(ctx context.Context, avatar *Avatar, sender MatrixAPI, ts time.Time) bool {
	if portal.AvatarID == avatar.ID && (portal.AvatarSet || portal.MXID == "") {
		return false
	}
	portal.AvatarID = avatar.ID
	if sender == nil {
		sender = portal.Bridge.Bot
	}
	if avatar.Remove {
		portal.AvatarMXC = ""
		portal.AvatarHash = [32]byte{}
	} else {
		newMXC, newHash, err := avatar.Reupload(ctx, sender, portal.AvatarHash)
		if err != nil {
			portal.AvatarSet = false
			zerolog.Ctx(ctx).Err(err).Msg("Failed to reupload room avatar")
			return true
		} else if newHash == portal.AvatarHash {
			return true
		}
		portal.AvatarMXC = newMXC
		portal.AvatarHash = newHash
	}
	portal.AvatarSet = portal.sendRoomMeta(ctx, sender, ts, event.StateRoomAvatar, "", &event.RoomAvatarEventContent{URL: portal.AvatarMXC})
	return true
}

func (portal *Portal) GetTopLevelParent() *Portal {
	// TODO ensure there's no infinite recursion?
	if portal.Parent == nil {
		// TODO return self if this is a space portal?
		return nil
	}
	return portal.Parent.GetTopLevelParent()
}

func (portal *Portal) getBridgeInfo() (string, event.BridgeEventContent) {
	bridgeInfo := event.BridgeEventContent{
		BridgeBot: portal.Bridge.Bot.GetMXID(),
		Creator:   portal.Bridge.Bot.GetMXID(),
		Protocol:  portal.Bridge.Network.GetName().AsBridgeInfoSection(),
		Channel: event.BridgeInfoSection{
			ID:          string(portal.ID),
			DisplayName: portal.Name,
			AvatarURL:   portal.AvatarMXC,
			// TODO external URL?
		},
		// TODO room type
	}
	if portal.Metadata.IsDirect {
		bridgeInfo.BeeperRoomType = "dm"
	} else if portal.Metadata.IsSpace {
		bridgeInfo.BeeperRoomType = "space"
	}
	parent := portal.GetTopLevelParent()
	if parent != nil {
		bridgeInfo.Network = &event.BridgeInfoSection{
			ID:          string(parent.ID),
			DisplayName: parent.Name,
			AvatarURL:   parent.AvatarMXC,
			// TODO external URL?
		}
	}
	// TODO use something globally unique instead of bridge ID?
	//      maybe ask the matrix connector to use serverName+appserviceID+bridgeID
	stateKey := string(portal.BridgeID)
	return stateKey, bridgeInfo
}

func (portal *Portal) UpdateBridgeInfo(ctx context.Context) {
	if portal.MXID == "" {
		return
	}
	stateKey, bridgeInfo := portal.getBridgeInfo()
	portal.sendRoomMeta(ctx, nil, time.Now(), event.StateBridge, stateKey, &bridgeInfo)
	portal.sendRoomMeta(ctx, nil, time.Now(), event.StateHalfShotBridge, stateKey, &bridgeInfo)
}

func (portal *Portal) sendStateWithIntentOrBot(ctx context.Context, sender MatrixAPI, eventType event.Type, stateKey string, content *event.Content, ts time.Time) (resp *mautrix.RespSendEvent, err error) {
	if sender == nil {
		sender = portal.Bridge.Bot
	}
	resp, err = sender.SendState(ctx, portal.MXID, eventType, stateKey, content, ts)
	if errors.Is(err, mautrix.MForbidden) && sender != portal.Bridge.Bot {
		if content.Raw == nil {
			content.Raw = make(map[string]any)
		}
		content.Raw["fi.mau.bridge.set_by"] = sender.GetMXID()
		resp, err = portal.Bridge.Bot.SendState(ctx, portal.MXID, event.StateRoomName, "", content, ts)
	}
	return
}

func (portal *Portal) sendRoomMeta(ctx context.Context, sender MatrixAPI, ts time.Time, eventType event.Type, stateKey string, content any) bool {
	if portal.MXID == "" {
		return false
	}
	_, err := portal.sendStateWithIntentOrBot(ctx, sender, eventType, stateKey, &event.Content{Parsed: content}, ts)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Str("event_type", eventType.Type).
			Msg("Failed to set room metadata")
		return false
	}
	return true
}

func (portal *Portal) GetInitialMemberList(ctx context.Context, members *ChatMemberList, source *UserLogin, pl *event.PowerLevelsEventContent) (invite, functional []id.UserID, err error) {
	if members == nil {
		invite = []id.UserID{source.UserMXID}
		return
	}
	var loginsInPortal []*UserLogin
	if members.CheckAllLogins {
		loginsInPortal, err = portal.Bridge.GetUserLoginsInPortal(ctx, portal.PortalKey)
		if err != nil {
			err = fmt.Errorf("failed to get user logins in portal: %w", err)
			return
		}
	}
	members.PowerLevels.Apply(pl)
	for _, member := range members.Members {
		intent, extraUserID := portal.getIntentAndUserMXIDFor(ctx, member.EventSender, source, loginsInPortal, 0)
		if extraUserID != "" {
			invite = append(invite, extraUserID)
			pl.EnsureUserLevel(extraUserID, member.PowerLevel)
			if intent != nil {
				// If intent is present along with a user ID, it's the ghost of a logged-in user,
				// so add it to the functional members list
				functional = append(functional, intent.GetMXID())
			}
		}
		if intent != nil {
			invite = append(invite, intent.GetMXID())
			pl.EnsureUserLevel(intent.GetMXID(), member.PowerLevel)
		}
	}
	return
}

func (portal *Portal) SyncParticipants(ctx context.Context, members *ChatMemberList, source *UserLogin, sender MatrixAPI, ts time.Time) error {
	var loginsInPortal []*UserLogin
	var err error
	if members.CheckAllLogins {
		loginsInPortal, err = portal.Bridge.GetUserLoginsInPortal(ctx, portal.PortalKey)
		if err != nil {
			return fmt.Errorf("failed to get user logins in portal: %w", err)
		}
	}
	if sender == nil {
		sender = portal.Bridge.Bot
	}
	log := zerolog.Ctx(ctx)
	currentPower, err := portal.Bridge.Matrix.GetPowerLevels(ctx, portal.MXID)
	if err != nil {
		return fmt.Errorf("failed to get current power levels: %w", err)
	}
	currentMembers, err := portal.Bridge.Matrix.GetMembers(ctx, portal.MXID)
	if err != nil {
		return fmt.Errorf("failed to get current members: %w", err)
	}
	delete(currentMembers, portal.Bridge.Bot.GetMXID())
	powerChanged := members.PowerLevels.Apply(currentPower)
	syncUser := func(extraUserID id.UserID, member ChatMember, hasIntent bool) bool {
		powerChanged = currentPower.EnsureUserLevel(extraUserID, member.PowerLevel) || powerChanged
		currentMember, ok := currentMembers[extraUserID]
		delete(currentMembers, extraUserID)
		if ok && currentMember.Membership == member.Membership {
			return false
		}
		if currentMember == nil {
			currentMember = &event.MemberEventContent{Membership: event.MembershipLeave}
		}
		if member.PrevMembership != "" && member.PrevMembership != currentMember.Membership {
			log.Trace().
				Stringer("user_id", extraUserID).
				Str("expected_prev_membership", string(member.PrevMembership)).
				Str("actual_prev_membership", string(currentMember.Membership)).
				Str("target_membership", string(member.Membership)).
				Msg("Not updating membership: prev membership mismatch")
			return false
		}
		content := &event.MemberEventContent{
			Membership:  member.Membership,
			Displayname: currentMember.Displayname,
			AvatarURL:   currentMember.AvatarURL,
		}
		wrappedContent := &event.Content{Parsed: content, Raw: make(map[string]any)}
		thisEvtSender := sender
		if member.Membership == event.MembershipJoin {
			content.Membership = event.MembershipInvite
			if hasIntent {
				wrappedContent.Raw["fi.mau.will_auto_accept"] = true
			}
			if thisEvtSender.GetMXID() == extraUserID {
				thisEvtSender = portal.Bridge.Bot
			}
		}
		if currentMember != nil && currentMember.Membership == event.MembershipBan && member.Membership != event.MembershipLeave {
			unbanContent := *content
			unbanContent.Membership = event.MembershipLeave
			wrappedUnbanContent := &event.Content{Parsed: &unbanContent}
			_, err = portal.sendStateWithIntentOrBot(ctx, thisEvtSender, event.StateMember, extraUserID.String(), wrappedUnbanContent, ts)
			if err != nil {
				log.Err(err).
					Stringer("target_user_id", extraUserID).
					Stringer("sender_user_id", thisEvtSender.GetMXID()).
					Str("prev_membership", string(currentMember.Membership)).
					Str("membership", string(member.Membership)).
					Msg("Failed to unban user to update membership")
			} else {
				log.Trace().
					Stringer("target_user_id", extraUserID).
					Stringer("sender_user_id", thisEvtSender.GetMXID()).
					Str("prev_membership", string(currentMember.Membership)).
					Str("membership", string(member.Membership)).
					Msg("Unbanned user to update membership")
			}
		}
		_, err = portal.sendStateWithIntentOrBot(ctx, thisEvtSender, event.StateMember, extraUserID.String(), wrappedContent, ts)
		if err != nil {
			log.Err(err).
				Stringer("target_user_id", extraUserID).
				Stringer("sender_user_id", thisEvtSender.GetMXID()).
				Str("prev_membership", string(currentMember.Membership)).
				Str("membership", string(member.Membership)).
				Msg("Failed to update user membership")
		} else {
			log.Trace().
				Stringer("target_user_id", extraUserID).
				Stringer("sender_user_id", thisEvtSender.GetMXID()).
				Str("prev_membership", string(currentMember.Membership)).
				Str("membership", string(member.Membership)).
				Msg("Updating membership in room")
		}
		return true
	}
	syncIntent := func(intent MatrixAPI, member ChatMember) {
		if !syncUser(intent.GetMXID(), member, true) {
			return
		}
		if member.Membership == event.MembershipJoin {
			err = intent.EnsureJoined(ctx, portal.MXID)
			if err != nil {
				log.Err(err).
					Stringer("user_id", intent.GetMXID()).
					Msg("Failed to ensure user is joined to room")
			}
		}
	}
	for _, member := range members.Members {
		intent, extraUserID := portal.getIntentAndUserMXIDFor(ctx, member.EventSender, source, loginsInPortal, 0)
		if intent != nil {
			syncIntent(intent, member)
		}
		if extraUserID != "" {
			syncUser(extraUserID, member, false)
		}
	}
	if powerChanged {
		_, err = portal.sendStateWithIntentOrBot(ctx, sender, event.StatePowerLevels, "", &event.Content{Parsed: currentPower}, ts)
		if err != nil {
			log.Err(err).Msg("Failed to update power levels")
		}
	}
	if members.IsFull {
		for extraMember, memberEvt := range currentMembers {
			if memberEvt.Membership == event.MembershipLeave || memberEvt.Membership == event.MembershipBan {
				continue
			}
			_, isGhost := portal.Bridge.Matrix.ParseGhostMXID(extraMember)
			if !isGhost && portal.Relay != nil {
				continue
			}
			_, err = portal.Bridge.Bot.SendState(ctx, portal.MXID, event.StateMember, extraMember.String(), &event.Content{
				Parsed: &event.MemberEventContent{
					Membership:  event.MembershipLeave,
					AvatarURL:   memberEvt.AvatarURL,
					Displayname: memberEvt.Displayname,
					Reason:      "User is not in remote chat",
				},
			}, time.Now())
			if err != nil {
				zerolog.Ctx(ctx).Err(err).
					Stringer("user_id", extraMember).
					Msg("Failed to remove user from room")
			}
		}
	}
	return nil
}

func (portal *Portal) updateUserLocalInfo(ctx context.Context, info *UserLocalPortalInfo, source *UserLogin) {
	if portal.MXID == "" || info == nil {
		return
	}
	dp := source.User.DoublePuppet(ctx)
	if dp == nil {
		return
	}
	if info.MutedUntil != nil {
		err := dp.MuteRoom(ctx, portal.MXID, *info.MutedUntil)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to mute room")
		}
	}
	if info.Tag != nil {
		err := dp.TagRoom(ctx, portal.MXID, *info.Tag, *info.Tag != "")
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to tag room")
		}
	}
}

func (portal *Portal) UpdateDisappearingSetting(ctx context.Context, setting database.DisappearingSetting, sender MatrixAPI, ts time.Time, implicit, save bool) bool {
	if setting.Timer == 0 {
		setting.Type = ""
	}
	if portal.Metadata.DisappearTimer == setting.Timer && portal.Metadata.DisappearType == setting.Type {
		return false
	}
	portal.Metadata.DisappearType = setting.Type
	portal.Metadata.DisappearTimer = setting.Timer
	if save {
		err := portal.Save(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to save portal to database after updating disappearing setting")
		}
	}
	content := &event.MessageEventContent{
		MsgType: event.MsgNotice,
		Body:    fmt.Sprintf("Disappearing messages set to %s", exfmt.Duration(setting.Timer)),
	}
	if implicit {
		content.Body = fmt.Sprintf("Automatically enabled disappearing message timer (%s) because incoming message is disappearing", exfmt.Duration(setting.Timer))
	} else if setting.Timer == 0 {
		content.Body = "Disappearing messages disabled"
	}
	if sender == nil {
		sender = portal.Bridge.Bot
	}
	_, err := sender.SendMessage(ctx, portal.MXID, event.EventMessage, &event.Content{
		Parsed: content,
	}, ts)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to send disappearing messages notice")
	} else {
		zerolog.Ctx(ctx).Debug().
			Dur("new_timer", portal.Metadata.DisappearTimer).
			Bool("implicit", implicit).
			Msg("Sent disappearing messages notice")
	}
	return true
}

func (portal *Portal) UpdateInfo(ctx context.Context, info *ChatInfo, source *UserLogin, sender MatrixAPI, ts time.Time) {
	changed := false
	if info.Name != nil {
		changed = portal.UpdateName(ctx, *info.Name, sender, ts) || changed
	}
	if info.Topic != nil {
		changed = portal.UpdateTopic(ctx, *info.Topic, sender, ts) || changed
	}
	if info.Avatar != nil {
		changed = portal.UpdateAvatar(ctx, info.Avatar, sender, ts) || changed
	}
	if info.Disappear != nil {
		changed = portal.UpdateDisappearingSetting(ctx, *info.Disappear, sender, ts, false, false) || changed
	}
	if info.JoinRule != nil {
		// TODO change detection instead of spamming this every time?
		portal.sendRoomMeta(ctx, sender, ts, event.StateJoinRules, "", info.JoinRule)
	}
	if info.Members != nil && portal.MXID != "" && source != nil {
		err := portal.SyncParticipants(ctx, info.Members, source, nil, time.Time{})
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to sync room members")
		}
		// TODO detect changes to functional members list?
	}
	if info.IsDirectChat != nil && portal.Metadata.IsDirect != *info.IsDirectChat {
		changed = true
		portal.Metadata.IsDirect = *info.IsDirectChat
	}
	if source != nil {
		source.MarkInPortal(ctx, portal)
		portal.updateUserLocalInfo(ctx, info.UserLocal, source)
	}
	if info.ExtraUpdates != nil {
		changed = info.ExtraUpdates(ctx, portal) || changed
	}
	if changed {
		portal.UpdateBridgeInfo(ctx)
		err := portal.Save(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to save portal to database after updating info")
		}
	}
}

func (portal *Portal) CreateMatrixRoom(ctx context.Context, source *UserLogin, info *ChatInfo) error {
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	if portal.MXID != "" {
		return nil
	}
	log := zerolog.Ctx(ctx).With().
		Str("action", "create matrix room").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Creating Matrix room")

	var err error
	if info == nil {
		info, err = source.Client.GetChatInfo(ctx, portal)
		if err != nil {
			log.Err(err).Msg("Failed to update portal info for creation")
			return err
		}
	}
	portal.UpdateInfo(ctx, info, source, nil, time.Time{})
	powerLevels := &event.PowerLevelsEventContent{
		Events: map[string]int{
			event.StateTombstone.Type:  100,
			event.StateServerACL.Type:  100,
			event.StateEncryption.Type: 100,
		},
		Users: map[id.UserID]int{},
	}
	initialMembers, extraFunctionalMembers, err := portal.GetInitialMemberList(ctx, info.Members, source, powerLevels)
	if err != nil {
		log.Err(err).Msg("Failed to process participant list for portal creation")
		return err
	}
	powerLevels.EnsureUserLevel(portal.Bridge.Bot.GetMXID(), 9001)

	req := mautrix.ReqCreateRoom{
		Visibility:         "private",
		Name:               portal.Name,
		Topic:              portal.Topic,
		CreationContent:    make(map[string]any),
		InitialState:       make([]*event.Event, 0, 6),
		Preset:             "private_chat",
		IsDirect:           portal.Metadata.IsDirect,
		PowerLevelOverride: powerLevels,
		BeeperLocalRoomID:  id.RoomID(fmt.Sprintf("!%s:%s", portal.ID, portal.Bridge.Matrix.ServerName())),
	}
	autoJoinInvites := portal.Bridge.Matrix.GetCapabilities().AutoJoinInvites
	if autoJoinInvites {
		req.BeeperInitialMembers = initialMembers
		// TODO remove this after initial_members is supported in hungryserv
		req.BeeperAutoJoinInvites = true
		req.Invite = initialMembers
	}
	if *info.IsSpace {
		req.CreationContent["type"] = event.RoomTypeSpace
		portal.Metadata.IsSpace = true
	}
	bridgeInfoStateKey, bridgeInfo := portal.getBridgeInfo()
	emptyString := ""

	req.InitialState = append(req.InitialState, &event.Event{
		StateKey: &emptyString,
		Type:     event.StateElementFunctionalMembers,
		Content: event.Content{Parsed: &event.ElementFunctionalMembersContent{
			ServiceMembers: append(extraFunctionalMembers, portal.Bridge.Bot.GetMXID()),
		}},
	}, &event.Event{
		StateKey: &bridgeInfoStateKey,
		Type:     event.StateHalfShotBridge,
		Content:  event.Content{Parsed: &bridgeInfo},
	}, &event.Event{
		StateKey: &bridgeInfoStateKey,
		Type:     event.StateBridge,
		Content:  event.Content{Parsed: &bridgeInfo},
	})
	if req.Topic == "" {
		// Add explicit topic event if topic is empty to ensure the event is set.
		// This ensures that there won't be an extra event later if PUT /state/... is called.
		req.InitialState = append(req.InitialState, &event.Event{
			StateKey: &emptyString,
			Type:     event.StateTopic,
			Content:  event.Content{Parsed: &event.TopicEventContent{Topic: ""}},
		})
	}
	if portal.AvatarMXC != "" {
		req.InitialState = append(req.InitialState, &event.Event{
			StateKey: &emptyString,
			Type:     event.StateRoomAvatar,
			Content:  event.Content{Parsed: &event.RoomAvatarEventContent{URL: portal.AvatarMXC}},
		})
	}
	if portal.Parent != nil {
		// TODO create parent portal if it doesn't exist?
		req.InitialState = append(req.InitialState, &event.Event{
			StateKey: (*string)(&portal.Parent.MXID),
			Type:     event.StateSpaceParent,
			Content: event.Content{Parsed: &event.SpaceParentEventContent{
				Via:       []string{portal.Bridge.Matrix.ServerName()},
				Canonical: true,
			}},
		})
	}
	if info.JoinRule != nil {
		req.InitialState = append(req.InitialState, &event.Event{
			Type:    event.StateJoinRules,
			Content: event.Content{Parsed: info.JoinRule},
		})
	}
	roomID, err := portal.Bridge.Bot.CreateRoom(ctx, &req)
	if err != nil {
		log.Err(err).Msg("Failed to create Matrix room")
		return err
	}
	log.Info().Stringer("room_id", roomID).Msg("Matrix room created")
	portal.AvatarSet = true
	portal.TopicSet = true
	portal.NameSet = true
	portal.MXID = roomID
	portal.Bridge.cacheLock.Lock()
	portal.Bridge.portalsByMXID[roomID] = portal
	portal.Bridge.cacheLock.Unlock()
	portal.updateLogger()
	err = portal.Save(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to save portal to database after creating Matrix room")
		return err
	}
	if portal.Parent != nil {
		// TODO add m.space.child event
	}
	portal.updateUserLocalInfo(ctx, info.UserLocal, source)
	if !autoJoinInvites {
		if info.Members == nil {
			dp := source.User.DoublePuppet(ctx)
			if dp != nil {
				err = dp.EnsureJoined(ctx, portal.MXID)
				if err != nil {
					log.Err(err).Msg("Failed to ensure user is joined to room after creation")
				}
			}
		} else {
			err = portal.SyncParticipants(ctx, info.Members, source, nil, time.Time{})
			if err != nil {
				log.Err(err).Msg("Failed to sync participants after room creation")
			}
		}
	}
	userPortals, err := portal.Bridge.DB.UserPortal.GetAllInPortal(ctx, portal.PortalKey)
	if err != nil {
		log.Err(err).Msg("Failed to get user logins in portal to add portal to spaces")
	} else {
		for _, up := range userPortals {
			login := portal.Bridge.GetCachedUserLoginByID(up.LoginID)
			if login != nil {
				login.inPortalCache.Remove(portal.PortalKey)
				go login.tryAddPortalToSpace(ctx, portal, up.CopyWithoutValues())
			}
		}
	}
	return nil
}

func (portal *Portal) Delete(ctx context.Context) error {
	err := portal.Bridge.DB.Portal.Delete(ctx, portal.PortalKey)
	if err != nil {
		return err
	}
	portal.Bridge.cacheLock.Lock()
	defer portal.Bridge.cacheLock.Unlock()
	portal.unlockedDeleteCache()
	return nil
}

func (portal *Portal) unlockedDelete(ctx context.Context) error {
	// TODO delete child portals?
	err := portal.Bridge.DB.Portal.Delete(ctx, portal.PortalKey)
	if err != nil {
		return err
	}
	portal.unlockedDeleteCache()
	return nil
}

func (portal *Portal) unlockedDeleteCache() {
	delete(portal.Bridge.portalsByKey, portal.PortalKey)
	if portal.MXID != "" {
		delete(portal.Bridge.portalsByMXID, portal.MXID)
	}
}

func (portal *Portal) Save(ctx context.Context) error {
	return portal.Bridge.DB.Portal.Update(ctx, portal.Portal)
}

func (portal *Portal) SetRelay(ctx context.Context, relay *UserLogin) error {
	portal.Relay = relay
	if relay == nil {
		portal.RelayLoginID = ""
	} else {
		portal.RelayLoginID = relay.ID
	}
	err := portal.Save(ctx)
	if err != nil {
		return err
	}
	return nil
}
