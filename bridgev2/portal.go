// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exslices"
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

	currentlyTyping     []id.UserID
	currentlyTypingLock sync.Mutex

	roomCreateLock sync.Mutex

	events chan portalEvent
}

const PortalEventBuffer = 64

func (br *Bridge) loadPortal(ctx context.Context, dbPortal *database.Portal, queryErr error, id *networkid.PortalID) (*Portal, error) {
	if queryErr != nil {
		return nil, fmt.Errorf("failed to query db: %w", queryErr)
	}
	if dbPortal == nil {
		if id == nil {
			return nil, nil
		}
		dbPortal = &database.Portal{
			BridgeID: br.ID,
			ID:       *id,
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
	}
	br.portalsByID[portal.ID] = portal
	if portal.MXID != "" {
		br.portalsByMXID[portal.MXID] = portal
	}
	if portal.ParentID != "" {
		var err error
		portal.Parent, err = br.unlockedGetPortalByID(ctx, portal.ParentID, false)
		if err != nil {
			return nil, fmt.Errorf("failed to load parent portal (%s): %w", portal.ParentID, err)
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

func (br *Bridge) unlockedGetPortalByID(ctx context.Context, id networkid.PortalID, onlyIfExists bool) (*Portal, error) {
	cached, ok := br.portalsByID[id]
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

func (br *Bridge) GetPortalByID(ctx context.Context, id networkid.PortalID) (*Portal, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.unlockedGetPortalByID(ctx, id, false)
}

func (br *Bridge) GetExistingPortalByID(ctx context.Context, id networkid.PortalID) (*Portal, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.unlockedGetPortalByID(ctx, id, true)
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

func (portal *Portal) FindPreferredLogin(ctx context.Context, user *User) (*UserLogin, error) {
	logins, err := portal.Bridge.DB.User.FindLoginsByPortalID(ctx, user.MXID, portal.ID)
	if err != nil {
		return nil, err
	}
	portal.Bridge.cacheLock.Lock()
	defer portal.Bridge.cacheLock.Unlock()
	for _, loginID := range logins {
		login, ok := user.logins[loginID]
		if ok && login.Client != nil {
			return login, nil
		}
	}
	// Portal has relay, use it
	if portal.Relay != nil {
		return nil, nil
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
		return firstLogin, nil
	} else {
		return nil, ErrNotLoggedIn
	}
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
		Stringer("event_id", evt.ID).
		Stringer("sender", sender.MXID).
		Logger()
	ctx := log.WithContext(context.TODO())
	login, err := portal.FindPreferredLogin(ctx, sender)
	if err != nil {
		log.Err(err).Msg("Failed to get user login to handle Matrix event")
		// TODO send metrics
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
			// TODO send metrics
			return
		}
		portal.handleMatrixReaction(ctx, login, evt)
	case event.EventRedaction:
		portal.handleMatrixRedaction(ctx, login, origSender, evt)
	case event.StateRoomName:
	case event.StateTopic:
	case event.StateRoomAvatar:
	case event.StateEncryption:
	}
}

func (portal *Portal) handleMatrixReceipts(evt *event.Event) {
	content, ok := evt.Content.Parsed.(event.ReceiptEventContent)
	if !ok {
		return
	}
	ctx := context.TODO()
	for evtID, receipts := range content {
		readReceipts, ok := receipts[event.ReceiptTypeRead]
		if !ok {
			continue
		}
		for userID, receipt := range readReceipts {
			sender, err := portal.Bridge.GetUserByMXID(ctx, userID)
			if err != nil {
				// TODO log
				return
			}
			portal.handleMatrixReadReceipt(ctx, sender, evtID, receipt)
		}
	}
}

func (portal *Portal) handleMatrixReadReceipt(ctx context.Context, user *User, eventID id.EventID, receipt event.ReadReceipt) {
	// TODO send read receipt(s) to network
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
	for range stoppedTyping {
		// TODO send typing stop events
	}
	for range startedTyping {
		// TODO send typing start events
	}
	portal.currentlyTyping = content.UserIDs
}

func (portal *Portal) periodicTypingUpdater() {
	for {
		// TODO make delay configurable by network connector
		time.Sleep(5 * time.Second)
		portal.currentlyTypingLock.Lock()
		if len(portal.currentlyTyping) == 0 {
			portal.currentlyTypingLock.Unlock()
			continue
		}
		// TODO send typing events
		portal.currentlyTypingLock.Unlock()
	}
}

func (portal *Portal) handleMatrixMessage(ctx context.Context, sender *UserLogin, origSender *OrigSender, evt *event.Event) {
	log := zerolog.Ctx(ctx)
	content, ok := evt.Content.Parsed.(*event.MessageEventContent)
	if !ok {
		log.Error().Type("content_type", evt.Content.Parsed).Msg("Unexpected parsed content type")
		// TODO send metrics
		return
	}
	if content.RelatesTo.GetReplaceID() != "" {
		portal.handleMatrixEdit(ctx, sender, origSender, evt, content)
		return
	}

	// TODO get capabilities from network connector
	threadsSupported := true
	repliesSupported := true
	var threadRoot, replyTo *database.Message
	var err error
	if threadsSupported {
		threadRootID := content.RelatesTo.GetThreadParent()
		if threadRootID != "" {
			threadRoot, err = portal.Bridge.DB.Message.GetPartByMXID(ctx, threadRootID)
			if err != nil {
				log.Err(err).Msg("Failed to get thread root message from database")
			}
		}
	}
	if repliesSupported {
		var replyToID id.EventID
		if threadsSupported {
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

	message, err := sender.Client.HandleMatrixMessage(ctx, &MatrixMessage{
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
		// TODO send metrics here or inside HandleMatrixMessage?
		return
	}
	if message.Metadata == nil {
		message.Metadata = make(map[string]any)
	}
	message.Metadata["sender_mxid"] = evt.Sender
	// Hack to ensure the ghost row exists
	// TODO move to better place (like login)
	portal.Bridge.GetGhostByID(ctx, message.SenderID)
	err = portal.Bridge.DB.Message.Insert(ctx, message)
	if err != nil {
		log.Err(err).Msg("Failed to save message to database")
	}
	// TODO send success metrics
}

func (portal *Portal) handleMatrixEdit(ctx context.Context, sender *UserLogin, origSender *OrigSender, evt *event.Event, content *event.MessageEventContent) {
	editTargetID := content.RelatesTo.GetReplaceID()
	log := zerolog.Ctx(ctx)
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Stringer("edit_target_mxid", editTargetID)
	})
	if content.NewContent != nil {
		content = content.NewContent
	}
	editTarget, err := portal.Bridge.DB.Message.GetPartByMXID(ctx, editTargetID)
	if err != nil {
		log.Err(err).Msg("Failed to get edit target message from database")
		// TODO send metrics
		return
	}
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("edit_target_remote_id", string(editTarget.ID))
	})
	err = sender.Client.HandleMatrixEdit(ctx, &MatrixEdit{
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
		// TODO send metrics here or inside HandleMatrixEdit?
		return
	}
	err = portal.Bridge.DB.Message.Update(ctx, editTarget)
	if err != nil {
		log.Err(err).Msg("Failed to save message to database after editing")
	}
	// TODO send success metrics
}

func (portal *Portal) handleMatrixReaction(ctx context.Context, sender *UserLogin, evt *event.Event) {

}

func (portal *Portal) handleMatrixRedaction(ctx context.Context, sender *UserLogin, origSender *OrigSender, evt *event.Event) {

}

func (portal *Portal) handleRemoteEvent(source *UserLogin, evt RemoteEvent) {
	log := portal.Log.With().
		Str("source_id", string(source.ID)).
		Str("action", "handle remote event").
		Logger()
	log.UpdateContext(evt.AddLogContext)
	ctx := log.WithContext(context.TODO())
	if portal.MXID == "" {
		if !evt.ShouldCreatePortal() {
			return
		}
		err := portal.CreateMatrixRoom(ctx, source)
		if err != nil {
			log.Err(err).Msg("Failed to create portal to handle event")
			// TODO error
			return
		}
	}
	switch evt.GetType() {
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
	}
}

func (portal *Portal) getIntentFor(ctx context.Context, sender EventSender, source *UserLogin) MatrixAPI {
	var intent MatrixAPI
	if sender.IsFromMe {
		intent = portal.Bridge.Matrix.UserIntent(source.User)
	}
	if intent == nil && sender.SenderLogin != "" {
		senderLogin := portal.Bridge.GetCachedUserLoginByID(sender.SenderLogin)
		if senderLogin != nil {
			intent = portal.Bridge.Matrix.UserIntent(senderLogin.User)
		}
	}
	if intent == nil {
		ghost, err := portal.Bridge.GetGhostByID(ctx, sender.Sender)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get ghost for message sender")
			return nil
		}
		// TODO update ghost info
		intent = ghost.Intent
	}
	return intent
}

func (portal *Portal) handleRemoteMessage(ctx context.Context, source *UserLogin, evt RemoteMessage) {
	log := zerolog.Ctx(ctx)
	converted, err := evt.ConvertMessage(ctx, portal)
	if err != nil {
		// TODO log and notify room?
		return
	}
	var relatesToRowID int64
	var replyTo, threadRoot, prevThreadEvent *database.Message
	if converted.ReplyTo != nil {
		replyTo, err = portal.Bridge.DB.Message.GetFirstOrSpecificPartByID(ctx, *converted.ReplyTo)
		if err != nil {
			log.Err(err).Msg("Failed to get reply target message from database")
		} else {
			relatesToRowID = replyTo.RowID
		}
	}
	if converted.ThreadRoot != nil {
		threadRoot, err = portal.Bridge.DB.Message.GetFirstOrSpecificPartByID(ctx, *converted.ThreadRoot)
		if err != nil {
			log.Err(err).Msg("Failed to get thread root message from database")
		} else {
			relatesToRowID = threadRoot.RowID
		}
		// TODO thread roots need to be saved in the database in a way that allows fetching
		//      the first bridged thread message even if the original one isn't bridged

		// TODO 2 fetch last event in thread properly
		prevThreadEvent = threadRoot
	}
	intent := portal.getIntentFor(ctx, converted.EventSender, source)
	if intent == nil {
		return
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
			replyTargetSenderMXID, ok := replyTo.Metadata["sender_mxid"].(string)
			if ok && !slices.Contains(part.Content.Mentions.UserIDs, id.UserID(replyTargetSenderMXID)) {
				part.Content.Mentions.UserIDs = append(part.Content.Mentions.UserIDs, id.UserID(replyTargetSenderMXID))
			}
		}
		resp, err := intent.SendMessage(ctx, portal.MXID, part.Type, &event.Content{
			Parsed: part.Content,
			Raw:    part.Extra,
		}, converted.Timestamp)
		if err != nil {
			log.Err(err).Str("part_id", string(part.ID)).Msg("Failed to send message part to Matrix")
			continue
		}
		if part.DBMetadata == nil {
			part.DBMetadata = make(map[string]any)
		}
		// TODO make metadata fields less hacky
		part.DBMetadata["sender_mxid"] = intent.GetMXID()
		dbMessage := &database.Message{
			ID:             converted.ID,
			PartID:         part.ID,
			MXID:           resp.EventID,
			RoomID:         portal.ID,
			SenderID:       converted.Sender,
			Timestamp:      converted.Timestamp,
			RelatesToRowID: relatesToRowID,
			Metadata:       part.DBMetadata,
		}
		err = portal.Bridge.DB.Message.Insert(ctx, dbMessage)
		if err != nil {
			log.Err(err).Str("part_id", string(part.ID)).Msg("Failed to save message part to database")
		}
		if prevThreadEvent != nil {
			prevThreadEvent = dbMessage
		}
	}
}

func (portal *Portal) handleRemoteEdit(ctx context.Context, source *UserLogin, evt RemoteEdit) {

}

func (portal *Portal) handleRemoteReaction(ctx context.Context, source *UserLogin, evt RemoteReaction) {

}

func (portal *Portal) handleRemoteReactionRemove(ctx context.Context, source *UserLogin, evt RemoteReactionRemove) {

}

func (portal *Portal) handleRemoteMessageRemove(ctx context.Context, source *UserLogin, evt RemoteMessageRemove) {

}

var stateElementFunctionalMembers = event.Type{Class: event.StateEventType, Type: "io.element.functional_members"}

type PortalInfo struct {
	Name      string
	Topic     string
	AvatarID  networkid.AvatarID
	AvatarMXC id.ContentURIString

	Members []networkid.UserID

	IsDirectChat bool
	IsSpace      bool
}

func (portal *Portal) CreateMatrixRoom(ctx context.Context, source *UserLogin) error {
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

	info, err := source.Client.GetChatInfo(ctx, portal)
	if err != nil {
		log.Err(err).Msg("Failed to update portal info for creation")
		return err
	}
	portal.Name = info.Name
	portal.Topic = info.Topic
	portal.AvatarID = info.AvatarID
	portal.AvatarMXC = info.AvatarMXC
	invite := make([]id.UserID, 0, len(info.Members)+1)
	inviteIntents := make([]MatrixAPI, 0, len(info.Members)+1)
	for _, memberID := range info.Members {
		ghost, err := portal.Bridge.GetGhostByID(ctx, memberID)
		if err != nil {
			log.Err(err).Str("memebr_id", string(memberID)).Msg("Failed to get portal member ghost")
		} else {
			invite = append(invite, ghost.MXID)
			inviteIntents = append(inviteIntents, ghost.Intent)
		}
	}
	// TODO should the source user mxid come from members?
	invite = append(invite, source.UserMXID)
	inviteIntents = append(inviteIntents, portal.Bridge.Matrix.UserIntent(source.User))

	req := mautrix.ReqCreateRoom{
		Visibility:      "private",
		Name:            portal.Name,
		Topic:           portal.Topic,
		CreationContent: make(map[string]any),
		InitialState:    make([]*event.Event, 0, 4),
		Preset:          "private_chat",
		IsDirect:        info.IsDirectChat,
		PowerLevelOverride: &event.PowerLevelsEventContent{
			Users: map[id.UserID]int{
				portal.Bridge.Bot.GetMXID(): 9001,
			},
		},
		BeeperLocalRoomID:    id.RoomID(fmt.Sprintf("!%s:%s", portal.ID, portal.Bridge.Matrix.ServerName())),
		BeeperInitialMembers: invite,
	}
	// TODO find this properly from the matrix connector
	isBeeper := true
	// TODO remove this after initial_members is supported in hungryserv
	if isBeeper {
		req.BeeperAutoJoinInvites = true
		req.Invite = invite
	}
	if info.IsSpace {
		req.CreationContent["type"] = event.RoomTypeSpace
	}
	emptyString := ""
	req.InitialState = append(req.InitialState, &event.Event{
		StateKey: &emptyString,
		Type:     stateElementFunctionalMembers,
		Content: event.Content{Raw: map[string]any{
			"service_members": []id.UserID{portal.Bridge.Bot.GetMXID()},
		}},
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
			// TODO change RoomAvatarEventContent to have id.ContentURIString instead of id.ContentURI?
			Content: event.Content{Raw: map[string]any{"url": portal.AvatarMXC}},
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
	err = portal.Bridge.DB.Portal.Update(ctx, portal.Portal)
	if err != nil {
		log.Err(err).Msg("Failed to save portal to database after creating Matrix room")
		return err
	}
	if portal.Parent != nil {
		// TODO add m.space.child event
	}
	if !isBeeper {
		for i, mxid := range invite {
			intent := inviteIntents[i]
			// TODO handle errors
			if intent != nil {
				intent.EnsureJoined(ctx, portal.MXID)
			} else {
				portal.Bridge.Bot.InviteUser(ctx, portal.MXID, mxid)
			}
		}
	}
	return nil
}
