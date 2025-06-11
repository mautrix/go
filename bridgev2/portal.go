// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exfmt"
	"go.mau.fi/util/exslices"
	"go.mau.fi/util/exsync"
	"go.mau.fi/util/ptr"
	"go.mau.fi/util/variationselector"
	"golang.org/x/exp/maps"
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
	evt     RemoteEvent
	source  *UserLogin
	evtType RemoteEventType
}

type portalCreateEvent struct {
	ctx    context.Context
	source *UserLogin
	info   *ChatInfo
	cb     func(error)
}

func (pme *portalMatrixEvent) isPortalEvent() {}
func (pre *portalRemoteEvent) isPortalEvent() {}
func (pre *portalCreateEvent) isPortalEvent() {}

type portalEvent interface {
	isPortalEvent()
}

type outgoingMessage struct {
	db        *database.Message
	evt       *event.Event
	ignore    bool
	handle    func(RemoteMessage, *database.Message) (bool, error)
	ackedAt   time.Time
	timeouted bool
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
	currentlyTypingGhosts *exsync.Set[id.UserID]

	outgoingMessages     map[networkid.TransactionID]*outgoingMessage
	outgoingMessagesLock sync.Mutex

	lastCapUpdate time.Time

	roomCreateLock sync.Mutex

	events chan portalEvent

	eventsLock sync.Mutex
	eventIdx   int
}

var PortalEventBuffer = 64

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

		currentlyTypingLogins: make(map[id.UserID]*UserLogin),
		currentlyTypingGhosts: exsync.NewSet[id.UserID](),
		outgoingMessages:      make(map[networkid.TransactionID]*outgoingMessage),
	}
	br.portalsByKey[portal.PortalKey] = portal
	if portal.MXID != "" {
		br.portalsByMXID[portal.MXID] = portal
	}
	var err error
	if portal.ParentKey.ID != "" {
		portal.Parent, err = br.UnlockedGetPortalByKey(ctx, portal.ParentKey, false)
		if err != nil {
			return nil, fmt.Errorf("failed to load parent portal (%s): %w", portal.ParentKey, err)
		}
	}
	if portal.RelayLoginID != "" {
		portal.Relay, err = br.unlockedGetExistingUserLoginByID(ctx, portal.RelayLoginID)
		if err != nil {
			return nil, fmt.Errorf("failed to load relay login (%s): %w", portal.RelayLoginID, err)
		}
	}
	portal.updateLogger()
	if PortalEventBuffer != 0 {
		portal.events = make(chan portalEvent, PortalEventBuffer)
		go portal.eventLoop()
	}
	return portal, nil
}

func (portal *Portal) updateLogger() {
	logWith := portal.Bridge.Log.With().Str("portal_id", string(portal.ID))
	if portal.MXID != "" {
		logWith = logWith.Stringer("portal_mxid", portal.MXID)
	}
	portal.Log = logWith.Logger()
}

func (br *Bridge) loadManyPortals(ctx context.Context, portals []*database.Portal) ([]*Portal, error) {
	output := make([]*Portal, 0, len(portals))
	for _, dbPortal := range portals {
		if cached, ok := br.portalsByKey[dbPortal.PortalKey]; ok {
			output = append(output, cached)
		} else {
			loaded, err := br.loadPortal(ctx, dbPortal, nil, nil)
			if err != nil {
				return nil, err
			} else if loaded != nil {
				output = append(output, loaded)
			}
		}
	}
	return output, nil
}

func (br *Bridge) UnlockedGetPortalByKey(ctx context.Context, key networkid.PortalKey, onlyIfExists bool) (*Portal, error) {
	if br.Config.SplitPortals && key.Receiver == "" {
		return nil, fmt.Errorf("receiver must always be set when split portals is enabled")
	}
	cached, ok := br.portalsByKey[key]
	if ok {
		return cached, nil
	}
	keyPtr := &key
	if onlyIfExists {
		keyPtr = nil
	}
	db, err := br.DB.Portal.GetByKey(ctx, key)
	return br.loadPortal(ctx, db, err, keyPtr)
}

func (br *Bridge) FindPortalReceiver(ctx context.Context, id networkid.PortalID, maybeReceiver networkid.UserLoginID) (networkid.PortalKey, error) {
	key := br.FindCachedPortalReceiver(id, maybeReceiver)
	if !key.IsEmpty() {
		return key, nil
	}
	key, err := br.DB.Portal.FindReceiver(ctx, id, maybeReceiver)
	if err != nil {
		return networkid.PortalKey{}, err
	}
	return key, nil
}

func (br *Bridge) FindCachedPortalReceiver(id networkid.PortalID, maybeReceiver networkid.UserLoginID) networkid.PortalKey {
	if br.Config.SplitPortals {
		return networkid.PortalKey{ID: id, Receiver: maybeReceiver}
	}
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	portal, ok := br.portalsByKey[networkid.PortalKey{
		ID:       id,
		Receiver: maybeReceiver,
	}]
	if ok {
		return portal.PortalKey
	}
	portal, ok = br.portalsByKey[networkid.PortalKey{ID: id}]
	if ok {
		return portal.PortalKey
	}
	return networkid.PortalKey{}
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

func (br *Bridge) GetAllPortalsWithMXID(ctx context.Context) ([]*Portal, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	rows, err := br.DB.Portal.GetAllWithMXID(ctx)
	if err != nil {
		return nil, err
	}
	return br.loadManyPortals(ctx, rows)
}

func (br *Bridge) GetAllPortals(ctx context.Context) ([]*Portal, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	rows, err := br.DB.Portal.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	return br.loadManyPortals(ctx, rows)
}

func (br *Bridge) GetDMPortalsWith(ctx context.Context, otherUserID networkid.UserID) ([]*Portal, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	rows, err := br.DB.Portal.GetAllDMsWith(ctx, otherUserID)
	if err != nil {
		return nil, err
	}
	return br.loadManyPortals(ctx, rows)
}

func (br *Bridge) GetPortalByKey(ctx context.Context, key networkid.PortalKey) (*Portal, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.UnlockedGetPortalByKey(ctx, key, false)
}

func (br *Bridge) GetExistingPortalByKey(ctx context.Context, key networkid.PortalKey) (*Portal, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	if key.Receiver == "" || br.Config.SplitPortals {
		return br.UnlockedGetPortalByKey(ctx, key, true)
	}
	cached, ok := br.portalsByKey[key]
	if ok {
		return cached, nil
	}
	cached, ok = br.portalsByKey[networkid.PortalKey{ID: key.ID}]
	if ok {
		return cached, nil
	}
	db, err := br.DB.Portal.GetByIDWithUncertainReceiver(ctx, key)
	return br.loadPortal(ctx, db, err, nil)
}

func (portal *Portal) queueEvent(ctx context.Context, evt portalEvent) {
	if PortalEventBuffer == 0 {
		portal.eventsLock.Lock()
		defer portal.eventsLock.Unlock()
		portal.eventIdx++
		portal.handleSingleEventAsync(portal.eventIdx, evt)
	} else {
		select {
		case portal.events <- evt:
		default:
			zerolog.Ctx(ctx).Error().
				Str("portal_id", string(portal.ID)).
				Msg("Portal event channel is full")
		}
	}
}

func (portal *Portal) eventLoop() {
	if cfg := portal.Bridge.Network.GetCapabilities().OutgoingMessageTimeouts; cfg != nil {
		ctx, cancel := context.WithCancel(portal.Log.WithContext(portal.Bridge.BackgroundCtx))
		go portal.pendingMessageTimeoutLoop(ctx, cfg)
		defer cancel()
	}
	i := 0
	for rawEvt := range portal.events {
		i++
		portal.handleSingleEventAsync(i, rawEvt)
	}
}

func (portal *Portal) handleSingleEventAsync(idx int, rawEvt any) {
	ctx := portal.getEventCtxWithLog(rawEvt, idx)
	if _, isCreate := rawEvt.(*portalCreateEvent); isCreate {
		portal.handleSingleEvent(ctx, rawEvt, func() {})
	} else if portal.Bridge.Config.AsyncEvents {
		go portal.handleSingleEvent(ctx, rawEvt, func() {})
	} else {
		log := zerolog.Ctx(ctx)
		doneCh := make(chan struct{})
		var backgrounded atomic.Bool
		start := time.Now()
		var handleDuration time.Duration
		go portal.handleSingleEvent(ctx, rawEvt, func() {
			handleDuration = time.Since(start)
			close(doneCh)
			if backgrounded.Load() {
				log.Debug().
					Time("started_at", start).
					Stringer("duration", handleDuration).
					Msg("Event that took too long finally finished handling")
			}
		})
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for i := 0; i < 10; i++ {
			select {
			case <-doneCh:
				if i > 0 {
					log.Debug().
						Time("started_at", start).
						Stringer("duration", handleDuration).
						Msg("Event that took long finished handling")
				}
				return
			case <-tick.C:
				log.Warn().
					Time("started_at", start).
					Msg("Event handling is taking long")
			}
		}
		log.Warn().
			Time("started_at", start).
			Msg("Event handling is taking too long, continuing in background")
		backgrounded.Store(true)
	}
}

func (portal *Portal) getEventCtxWithLog(rawEvt any, idx int) context.Context {
	var logWith zerolog.Context
	switch evt := rawEvt.(type) {
	case *portalMatrixEvent:
		logWith = portal.Log.With().Int("event_loop_index", idx).
			Str("action", "handle matrix event").
			Stringer("event_id", evt.evt.ID).
			Str("event_type", evt.evt.Type.Type)
		if evt.evt.Type.Class != event.EphemeralEventType {
			logWith = logWith.
				Stringer("event_id", evt.evt.ID).
				Stringer("sender", evt.sender.MXID)
		}
	case *portalRemoteEvent:
		evt.evtType = evt.evt.GetType()
		logWith = portal.Log.With().Int("event_loop_index", idx).
			Str("action", "handle remote event").
			Str("source_id", string(evt.source.ID)).
			Stringer("bridge_evt_type", evt.evtType)
		logWith = evt.evt.AddLogContext(logWith)
		if remoteSender := evt.evt.GetSender(); remoteSender.Sender != "" || remoteSender.IsFromMe {
			logWith = logWith.Object("remote_sender", remoteSender)
		}
		if remoteMsg, ok := evt.evt.(RemoteMessage); ok {
			if remoteMsgID := remoteMsg.GetID(); remoteMsgID != "" {
				logWith = logWith.Str("remote_message_id", string(remoteMsgID))
			}
		}
		if remoteMsg, ok := evt.evt.(RemoteEventWithTargetMessage); ok {
			if targetMsgID := remoteMsg.GetTargetMessage(); targetMsgID != "" {
				logWith = logWith.Str("remote_target_message_id", string(targetMsgID))
			}
		}
		if remoteMsg, ok := evt.evt.(RemoteEventWithStreamOrder); ok {
			if remoteStreamOrder := remoteMsg.GetStreamOrder(); remoteStreamOrder != 0 {
				logWith = logWith.Int64("remote_stream_order", remoteStreamOrder)
			}
		}
	case *portalCreateEvent:
		return evt.ctx
	}
	return logWith.Logger().WithContext(portal.Bridge.BackgroundCtx)
}

func (portal *Portal) handleSingleEvent(ctx context.Context, rawEvt any, doneCallback func()) {
	log := zerolog.Ctx(ctx)
	defer func() {
		doneCallback()
		if err := recover(); err != nil {
			logEvt := log.Error()
			if realErr, ok := err.(error); ok {
				logEvt = logEvt.Err(realErr)
			} else {
				logEvt = logEvt.Any(zerolog.ErrorFieldName, err)
			}
			logEvt.
				Bytes("stack", debug.Stack()).
				Msg("Event handling panicked")
			switch evt := rawEvt.(type) {
			case *portalMatrixEvent:
				if evt.evt.ID != "" {
					go portal.sendErrorStatus(ctx, evt.evt, ErrPanicInEventHandler)
				}
			case *portalCreateEvent:
				evt.cb(fmt.Errorf("portal creation panicked"))
			}
		}
	}()
	switch evt := rawEvt.(type) {
	case *portalMatrixEvent:
		portal.handleMatrixEvent(ctx, evt.sender, evt.evt)
	case *portalRemoteEvent:
		portal.handleRemoteEvent(ctx, evt.source, evt.evtType, evt.evt)
	case *portalCreateEvent:
		evt.cb(portal.createMatrixRoomInLoop(evt.ctx, evt.source, evt.info, nil))
	default:
		panic(fmt.Errorf("illegal type %T in eventLoop", evt))
	}
}

func (portal *Portal) FindPreferredLogin(ctx context.Context, user *User, allowRelay bool) (*UserLogin, *database.UserPortal, error) {
	if portal.Receiver != "" {
		login, err := portal.Bridge.GetExistingUserLoginByID(ctx, portal.Receiver)
		if err != nil {
			return nil, nil, err
		}
		if login == nil || login.UserMXID != user.MXID || !login.Client.IsLoggedIn() {
			if allowRelay && portal.Relay != nil {
				return nil, nil, nil
			}
			// TODO different error for this case?
			return nil, nil, ErrNotLoggedIn
		}
		up, err := portal.Bridge.DB.UserPortal.Get(ctx, login.UserLogin, portal.PortalKey)
		return login, up, err
	}
	logins, err := portal.Bridge.DB.UserPortal.GetAllForUserInPortal(ctx, user.MXID, portal.PortalKey)
	if err != nil {
		return nil, nil, err
	}
	portal.Bridge.cacheLock.Lock()
	defer portal.Bridge.cacheLock.Unlock()
	for _, up := range logins {
		login, ok := user.logins[up.LoginID]
		if ok && login.Client != nil && login.Client.IsLoggedIn() {
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
	if firstLogin != nil && firstLogin.Client.IsLoggedIn() {
		zerolog.Ctx(ctx).Warn().
			Str("chosen_login_id", string(firstLogin.ID)).
			Msg("No usable user portal rows found, returning random login")
		return firstLogin, nil, nil
	} else {
		return nil, nil, ErrNotLoggedIn
	}
}

func (portal *Portal) sendSuccessStatus(ctx context.Context, evt *event.Event, streamOrder int64, newEventID id.EventID) {
	info := StatusEventInfoFromEvent(evt)
	info.StreamOrder = streamOrder
	if newEventID != evt.ID {
		info.NewEventID = newEventID
	}
	portal.Bridge.Matrix.SendMessageStatus(ctx, &MessageStatus{Status: event.MessageStatusSuccess}, info)
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

func (portal *Portal) checkConfusableName(ctx context.Context, userID id.UserID, name string) bool {
	conn, ok := portal.Bridge.Matrix.(MatrixConnectorWithNameDisambiguation)
	if !ok {
		return false
	}
	confusableWith, err := conn.IsConfusableName(ctx, portal.MXID, userID, name)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to check if name is confusable")
		return true
	}
	for _, confusable := range confusableWith {
		// Don't disambiguate names that only conflict with ghosts of this bridge
		if !portal.Bridge.IsGhostMXID(confusable) {
			return true
		}
	}
	return false
}

func (portal *Portal) handleMatrixEvent(ctx context.Context, sender *User, evt *event.Event) {
	log := zerolog.Ctx(ctx)
	if evt.Mautrix.EventSource&event.SourceEphemeral != 0 {
		switch evt.Type {
		case event.EphemeralEventReceipt:
			portal.handleMatrixReceipts(ctx, evt)
		case event.EphemeralEventTyping:
			portal.handleMatrixTyping(ctx, evt)
		}
		return
	}
	login, _, err := portal.FindPreferredLogin(ctx, sender, true)
	if err != nil {
		log.Err(err).Msg("Failed to get user login to handle Matrix event")
		if errors.Is(err, ErrNotLoggedIn) {
			shouldSendNotice := evt.Content.AsMessage().MsgType != event.MsgNotice
			portal.sendErrorStatus(ctx, evt, WrapErrorInStatus(err).WithMessage("You're not logged in").WithIsCertain(true).WithSendNotice(shouldSendNotice))
		} else {
			portal.sendErrorStatus(ctx, evt, WrapErrorInStatus(err).WithMessage("Failed to get login to handle event").WithIsCertain(true).WithSendNotice(true))
		}
		return
	}
	var origSender *OrigSender
	if login == nil {
		login = portal.Relay
		origSender = &OrigSender{
			User:   sender,
			UserID: sender.MXID,
		}

		memberInfo, err := portal.Bridge.Matrix.GetMemberInfo(ctx, portal.MXID, sender.MXID)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to get member info for user being relayed")
		} else if memberInfo != nil {
			origSender.MemberEventContent = *memberInfo
			if memberInfo.Displayname == "" {
				origSender.DisambiguatedName = sender.MXID.String()
			} else if origSender.RequiresDisambiguation = portal.checkConfusableName(ctx, sender.MXID, memberInfo.Displayname); origSender.RequiresDisambiguation {
				origSender.DisambiguatedName = fmt.Sprintf("%s (%s)", memberInfo.Displayname, sender.MXID)
			} else {
				origSender.DisambiguatedName = memberInfo.Displayname
			}
		} else {
			origSender.DisambiguatedName = sender.MXID.String()
		}
		origSender.FormattedName = portal.Bridge.Config.Relay.FormatName(origSender)
	}
	// Copy logger because many of the handlers will use UpdateContext
	ctx = log.With().Str("login_id", string(login.ID)).Logger().WithContext(ctx)
	switch evt.Type {
	case event.EventMessage, event.EventSticker, event.EventUnstablePollStart, event.EventUnstablePollResponse:
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
		// TODO?
	case event.AccountDataMarkedUnread:
		handleMatrixAccountData(portal, ctx, login, evt, MarkedUnreadHandlingNetworkAPI.HandleMarkedUnread)
	case event.AccountDataRoomTags:
		handleMatrixAccountData(portal, ctx, login, evt, TagHandlingNetworkAPI.HandleRoomTag)
	case event.AccountDataBeeperMute:
		handleMatrixAccountData(portal, ctx, login, evt, MuteHandlingNetworkAPI.HandleMute)
	case event.StateMember:
		portal.handleMatrixMembership(ctx, login, origSender, evt)
	case event.StatePowerLevels:
		portal.handleMatrixPowerLevels(ctx, login, origSender, evt)
	}
}

func (portal *Portal) handleMatrixReceipts(ctx context.Context, evt *event.Event) {
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
	log := zerolog.Ctx(ctx)
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.
			Stringer("event_id", eventID).
			Stringer("user_id", user.MXID).
			Stringer("receipt_ts", receipt.Timestamp)
	})
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
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("user_login_id", string(login.ID))
	})
	evt := &MatrixReadReceipt{
		Portal:  portal,
		EventID: eventID,
		Receipt: receipt,
	}
	if userPortal == nil {
		userPortal = database.UserPortalFor(login.UserLogin, portal.PortalKey)
	} else {
		evt.LastRead = userPortal.LastRead
		userPortal = userPortal.CopyWithoutValues()
	}
	evt.ExactMessage, err = portal.Bridge.DB.Message.GetPartByMXID(ctx, eventID)
	if err != nil {
		log.Err(err).Msg("Failed to get exact message from database")
	} else if evt.ExactMessage != nil {
		log.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("exact_message_id", string(evt.ExactMessage.ID)).Time("exact_message_ts", evt.ExactMessage.Timestamp)
		})
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

func (portal *Portal) handleMatrixTyping(ctx context.Context, evt *event.Event) {
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

func (portal *Portal) checkMessageContentCaps(ctx context.Context, caps *event.RoomFeatures, content *event.MessageEventContent, evt *event.Event) bool {
	switch content.MsgType {
	case event.MsgText, event.MsgNotice, event.MsgEmote:
		// No checks for now, message length is safer to check after conversion inside connector
	case event.MsgLocation:
		if caps.LocationMessage.Reject() {
			portal.sendErrorStatus(ctx, evt, ErrLocationMessagesNotAllowed)
			return false
		}
	case event.MsgImage, event.MsgAudio, event.MsgVideo, event.MsgFile, event.CapMsgSticker:
		capMsgType := content.GetCapMsgType()
		feat, ok := caps.File[capMsgType]
		if !ok {
			portal.sendErrorStatus(ctx, evt, ErrUnsupportedMessageType)
			return false
		}
		if content.MsgType != event.CapMsgSticker &&
			content.FileName != "" &&
			content.Body != content.FileName &&
			feat.Caption.Reject() {
			portal.sendErrorStatus(ctx, evt, ErrCaptionsNotAllowed)
			return false
		}
		if content.Info != nil && content.Info.MimeType != "" {
			if feat.GetMimeSupport(content.Info.MimeType).Reject() {
				portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w (%s in %s)", ErrUnsupportedMediaType, content.Info.MimeType, capMsgType))
				return false
			}
		}
		fallthrough
	default:
	}
	return true
}

func (portal *Portal) parseInputTransactionID(origSender *OrigSender, evt *event.Event) networkid.RawTransactionID {
	if origSender != nil || !strings.HasPrefix(evt.ID.String(), database.NetworkTxnMXIDPrefix) {
		return ""
	}
	return networkid.RawTransactionID(strings.TrimPrefix(evt.ID.String(), database.NetworkTxnMXIDPrefix))
}

func (portal *Portal) handleMatrixMessage(ctx context.Context, sender *UserLogin, origSender *OrigSender, evt *event.Event) {
	log := zerolog.Ctx(ctx)
	var relatesTo *event.RelatesTo
	var msgContent *event.MessageEventContent
	var pollContent *event.PollStartEventContent
	var pollResponseContent *event.PollResponseEventContent
	var ok bool
	if evt.Type == event.EventUnstablePollStart {
		pollContent, ok = evt.Content.Parsed.(*event.PollStartEventContent)
		relatesTo = pollContent.RelatesTo
	} else if evt.Type == event.EventUnstablePollResponse {
		pollResponseContent, ok = evt.Content.Parsed.(*event.PollResponseEventContent)
		relatesTo = &pollResponseContent.RelatesTo
	} else {
		msgContent, ok = evt.Content.Parsed.(*event.MessageEventContent)
		relatesTo = msgContent.RelatesTo
		if evt.Type == event.EventSticker {
			msgContent.MsgType = event.CapMsgSticker
		}
		if msgContent.MsgType == event.MsgNotice && !portal.Bridge.Config.BridgeNotices {
			portal.sendErrorStatus(ctx, evt, ErrIgnoringMNotice)
			return
		}
	}
	if !ok {
		log.Error().Type("content_type", evt.Content.Parsed).Msg("Unexpected parsed content type")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: %T", ErrUnexpectedParsedContentType, evt.Content.Parsed))
		return
	}
	caps := sender.Client.GetCapabilities(ctx, portal)

	if relatesTo.GetReplaceID() != "" {
		if msgContent == nil {
			log.Warn().Msg("Ignoring edit of poll")
			portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w of polls", ErrEditsNotSupported))
			return
		}
		portal.handleMatrixEdit(ctx, sender, origSender, evt, msgContent, caps)
		return
	}
	var err error
	if origSender != nil {
		if msgContent == nil {
			log.Debug().Msg("Ignoring poll event from relayed user")
			portal.sendErrorStatus(ctx, evt, ErrIgnoringPollFromRelayedUser)
			return
		}
		msgContent, err = portal.Bridge.Config.Relay.FormatMessage(msgContent, origSender)
		if err != nil {
			log.Err(err).Msg("Failed to format message for relaying")
			portal.sendErrorStatus(ctx, evt, err)
			return
		}
	}
	if msgContent != nil {
		if !portal.checkMessageContentCaps(ctx, caps, msgContent, evt) {
			return
		}
	} else if pollResponseContent != nil || pollContent != nil {
		if _, ok = sender.Client.(PollHandlingNetworkAPI); !ok {
			log.Debug().Msg("Ignoring poll event as network connector doesn't implement PollHandlingNetworkAPI")
			portal.sendErrorStatus(ctx, evt, ErrPollsNotSupported)
			return
		}
	}

	var threadRoot, replyTo, voteTo *database.Message
	if evt.Type == event.EventUnstablePollResponse {
		voteTo, err = portal.Bridge.DB.Message.GetPartByMXID(ctx, relatesTo.GetReferenceID())
		if err != nil {
			log.Err(err).Msg("Failed to get poll target message from database")
			// TODO send status
			return
		} else if voteTo == nil {
			log.Warn().Stringer("vote_to_id", relatesTo.GetReferenceID()).Msg("Poll target message not found")
			// TODO send status
			return
		}
	}
	var replyToID id.EventID
	threadRootID := relatesTo.GetThreadParent()
	if caps.Thread.Partial() {
		replyToID = relatesTo.GetNonFallbackReplyTo()
		if threadRootID != "" {
			threadRoot, err = portal.Bridge.DB.Message.GetPartByMXID(ctx, threadRootID)
			if err != nil {
				log.Err(err).Msg("Failed to get thread root message from database")
			} else if threadRoot == nil {
				log.Warn().Stringer("thread_root_id", threadRootID).Msg("Thread root message not found")
			}
		}
	} else {
		replyToID = relatesTo.GetReplyTo()
	}
	if replyToID != "" && (caps.Reply.Partial() || caps.Thread.Partial()) {
		replyTo, err = portal.Bridge.DB.Message.GetPartByMXID(ctx, replyToID)
		if err != nil {
			log.Err(err).Msg("Failed to get reply target message from database")
		} else if replyTo == nil {
			log.Warn().Stringer("reply_to_id", replyToID).Msg("Reply target message not found")
		} else {
			// Support replying to threads from non-thread-capable clients.
			// The fallback happens if the message is not a Matrix thread and either
			// * the replied-to message is in a thread, or
			// * the network only supports threads (assume the user wants to start a new thread)
			if caps.Thread.Partial() && threadRoot == nil && (replyTo.ThreadRoot != "" || !caps.Reply.Partial()) {
				threadRootRemoteID := replyTo.ThreadRoot
				if threadRootRemoteID == "" {
					threadRootRemoteID = replyTo.ID
				}
				threadRoot, err = portal.Bridge.DB.Message.GetFirstThreadMessage(ctx, portal.PortalKey, threadRootRemoteID)
				if err != nil {
					log.Err(err).Msg("Failed to get thread root message from database (via reply fallback)")
				}
			}
			if !caps.Reply.Partial() {
				replyTo = nil
			}
		}
	}

	wrappedMsgEvt := &MatrixMessage{
		MatrixEventBase: MatrixEventBase[*event.MessageEventContent]{
			Event:      evt,
			Content:    msgContent,
			OrigSender: origSender,
			Portal:     portal,

			InputTransactionID: portal.parseInputTransactionID(origSender, evt),
		},
		ThreadRoot: threadRoot,
		ReplyTo:    replyTo,
	}
	if portal.Bridge.Config.DeduplicateMatrixMessages {
		if part, err := portal.Bridge.DB.Message.GetPartByTxnID(ctx, portal.Receiver, evt.ID, wrappedMsgEvt.InputTransactionID); err != nil {
			log.Err(err).Msg("Failed to check db if message is already sent")
		} else if part != nil {
			log.Debug().
				Stringer("message_mxid", part.MXID).
				Stringer("input_event_id", evt.ID).
				Msg("Message already sent, ignoring")
			return
		}
	}

	var resp *MatrixMessageResponse
	if msgContent != nil {
		resp, err = sender.Client.HandleMatrixMessage(ctx, wrappedMsgEvt)
	} else if pollContent != nil {
		resp, err = sender.Client.(PollHandlingNetworkAPI).HandleMatrixPollStart(ctx, &MatrixPollStart{
			MatrixMessage: *wrappedMsgEvt,
			Content:       pollContent,
		})
	} else if pollResponseContent != nil {
		resp, err = sender.Client.(PollHandlingNetworkAPI).HandleMatrixPollVote(ctx, &MatrixPollVote{
			MatrixMessage: *wrappedMsgEvt,
			VoteTo:        voteTo,
			Content:       pollResponseContent,
		})
	} else {
		log.Error().Msg("Failed to handle Matrix message: all contents are nil?")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("all contents are nil"))
		return
	}
	if err != nil {
		log.Err(err).Msg("Failed to handle Matrix message")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}
	message := wrappedMsgEvt.fillDBMessage(resp.DB)
	if resp.Pending {
		for _, save := range wrappedMsgEvt.pendingSaves {
			save.ackedAt = time.Now()
		}
	} else {
		if resp.DB == nil {
			log.Error().Msg("Network connector didn't return a message to save")
		} else {
			if portal.Bridge.Config.OutgoingMessageReID {
				message.MXID = portal.Bridge.Matrix.GenerateDeterministicEventID(portal.MXID, portal.PortalKey, message.ID, message.PartID)
			}
			// Hack to ensure the ghost row exists
			// TODO move to better place (like login)
			portal.Bridge.GetGhostByID(ctx, message.SenderID)
			err = portal.Bridge.DB.Message.Insert(ctx, message)
			if err != nil {
				log.Err(err).Msg("Failed to save message to database")
			} else if resp.PostSave != nil {
				resp.PostSave(ctx, message)
			}
			if resp.RemovePending != "" {
				portal.outgoingMessagesLock.Lock()
				delete(portal.outgoingMessages, resp.RemovePending)
				portal.outgoingMessagesLock.Unlock()
			}
		}
		portal.sendSuccessStatus(ctx, evt, resp.StreamOrder, message.MXID)
	}
	if portal.Disappear.Type != database.DisappearingTypeNone {
		go portal.Bridge.DisappearLoop.Add(ctx, &database.DisappearingMessage{
			RoomID:  portal.MXID,
			EventID: message.MXID,
			DisappearingSetting: database.DisappearingSetting{
				Type:        portal.Disappear.Type,
				Timer:       portal.Disappear.Timer,
				DisappearAt: message.Timestamp.Add(portal.Disappear.Timer),
			},
		})
	}
}

// AddPendingToIgnore adds a transaction ID that should be ignored if encountered as a new message.
//
// This should be used when the network connector will return the real message ID from HandleMatrixMessage.
// The [MatrixMessageResponse] should include RemovePending with the transaction ID sto remove it from the lit
// after saving to database.
//
// See also: [MatrixMessage.AddPendingToSave]
func (evt *MatrixMessage) AddPendingToIgnore(txnID networkid.TransactionID) {
	evt.Portal.outgoingMessagesLock.Lock()
	evt.Portal.outgoingMessages[txnID] = &outgoingMessage{
		ignore: true,
	}
	evt.Portal.outgoingMessagesLock.Unlock()
}

// AddPendingToSave adds a transaction ID that should be processed and pointed at the existing event if encountered.
//
// This should be used when the network connector returns `Pending: true` from HandleMatrixMessage,
// i.e. when the network connector does not know the message ID at the end of the handler.
// The [MatrixMessageResponse] should set Pending to true to prevent saving the returned message to the database.
//
// The provided function will be called when the message is encountered.
func (evt *MatrixMessage) AddPendingToSave(message *database.Message, txnID networkid.TransactionID, handleEcho RemoteEchoHandler) {
	pending := &outgoingMessage{
		db:     evt.fillDBMessage(message),
		evt:    evt.Event,
		handle: handleEcho,
	}
	evt.Portal.outgoingMessagesLock.Lock()
	evt.Portal.outgoingMessages[txnID] = pending
	evt.pendingSaves = append(evt.pendingSaves, pending)
	evt.Portal.outgoingMessagesLock.Unlock()
}

// RemovePending removes a transaction ID from the list of pending messages.
// This should only be called if sending the message fails.
func (evt *MatrixMessage) RemovePending(txnID networkid.TransactionID) {
	evt.Portal.outgoingMessagesLock.Lock()
	pendingSave := evt.Portal.outgoingMessages[txnID]
	if pendingSave != nil {
		evt.pendingSaves = slices.DeleteFunc(evt.pendingSaves, func(save *outgoingMessage) bool {
			return save == pendingSave
		})
	}
	delete(evt.Portal.outgoingMessages, txnID)
	evt.Portal.outgoingMessagesLock.Unlock()
}

func (evt *MatrixMessage) fillDBMessage(message *database.Message) *database.Message {
	if message == nil {
		message = &database.Message{}
	}
	if message.MXID == "" {
		message.MXID = evt.Event.ID
	}
	if message.Room.ID == "" {
		message.Room = evt.Portal.PortalKey
	}
	if message.Timestamp.IsZero() {
		message.Timestamp = time.UnixMilli(evt.Event.Timestamp)
	}
	if message.ReplyTo.MessageID == "" && evt.ReplyTo != nil {
		message.ReplyTo.MessageID = evt.ReplyTo.ID
		message.ReplyTo.PartID = &evt.ReplyTo.PartID
	}
	if message.ThreadRoot == "" && evt.ThreadRoot != nil {
		message.ThreadRoot = evt.ThreadRoot.ID
		if evt.ThreadRoot.ThreadRoot != "" {
			message.ThreadRoot = evt.ThreadRoot.ThreadRoot
		}
	}
	if message.SenderMXID == "" {
		message.SenderMXID = evt.Event.Sender
	}
	if message.SendTxnID != "" {
		message.SendTxnID = evt.InputTransactionID
	}
	return message
}

func (portal *Portal) pendingMessageTimeoutLoop(ctx context.Context, cfg *OutgoingTimeoutConfig) {
	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			portal.checkPendingMessages(ctx, cfg)
		case <-ctx.Done():
			return
		}
	}
}

func (portal *Portal) checkPendingMessages(ctx context.Context, cfg *OutgoingTimeoutConfig) {
	portal.outgoingMessagesLock.Lock()
	defer portal.outgoingMessagesLock.Unlock()
	for _, msg := range portal.outgoingMessages {
		if msg.evt != nil && !msg.timeouted {
			if cfg.NoEchoTimeout > 0 && !msg.ackedAt.IsZero() && time.Since(msg.ackedAt) > cfg.NoEchoTimeout {
				msg.timeouted = true
				portal.sendErrorStatus(ctx, msg.evt, ErrRemoteEchoTimeout.WithMessage(cfg.NoEchoMessage))
			} else if cfg.NoAckTimeout > 0 && time.Since(msg.db.Timestamp) > cfg.NoAckTimeout {
				msg.timeouted = true
				portal.sendErrorStatus(ctx, msg.evt, ErrRemoteAckTimeout.WithMessage(cfg.NoAckMessage))
			}
		}
	}
}

func (portal *Portal) handleMatrixEdit(ctx context.Context, sender *UserLogin, origSender *OrigSender, evt *event.Event, content *event.MessageEventContent, caps *event.RoomFeatures) {
	log := zerolog.Ctx(ctx)
	editTargetID := content.RelatesTo.GetReplaceID()
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Stringer("edit_target_mxid", editTargetID)
	})
	if content.NewContent != nil {
		content = content.NewContent
		if evt.Type == event.EventSticker {
			content.MsgType = event.CapMsgSticker
		}
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
	} else if !caps.Edit.Partial() {
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
	} else if caps.EditMaxAge != nil && caps.EditMaxAge.Duration > 0 && time.Since(editTarget.Timestamp) > caps.EditMaxAge.Duration {
		portal.sendErrorStatus(ctx, evt, ErrEditTargetTooOld)
		return
	} else if caps.EditMaxCount > 0 && editTarget.EditCount >= caps.EditMaxCount {
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

			InputTransactionID: portal.parseInputTransactionID(origSender, evt),
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
	// TODO allow returning stream order from HandleMatrixEdit
	portal.sendSuccessStatus(ctx, evt, 0, "")
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

			InputTransactionID: portal.parseInputTransactionID(nil, evt),
		},
		TargetMessage: reactionTarget,
	}
	preResp, err := reactingAPI.PreHandleMatrixReaction(ctx, react)
	if err != nil {
		log.Err(err).Msg("Failed to pre-handle Matrix reaction")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}
	var deterministicID id.EventID
	if portal.Bridge.Config.OutgoingMessageReID {
		deterministicID = portal.Bridge.Matrix.GenerateReactionEventID(portal.MXID, reactionTarget, preResp.SenderID, preResp.EmojiID)
	}
	existing, err := portal.Bridge.DB.Reaction.GetByID(ctx, portal.Receiver, reactionTarget.ID, reactionTarget.PartID, preResp.SenderID, preResp.EmojiID)
	if err != nil {
		log.Err(err).Msg("Failed to check if reaction is a duplicate")
		return
	} else if existing != nil {
		if existing.EmojiID != "" || existing.Emoji == preResp.Emoji {
			log.Debug().Msg("Ignoring duplicate reaction")
			portal.sendSuccessStatus(ctx, evt, 0, deterministicID)
			return
		}
		react.ReactionToOverride = existing
		_, err = portal.Bridge.Bot.SendMessage(ctx, portal.MXID, event.EventRedaction, &event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: existing.MXID,
			},
		}, nil)
		if err != nil {
			log.Err(err).Msg("Failed to remove old reaction")
		}
	}
	react.PreHandleResp = &preResp
	if preResp.MaxReactions > 0 {
		allReactions, err := portal.Bridge.DB.Reaction.GetAllToMessageBySender(ctx, portal.Receiver, reactionTarget.ID, preResp.SenderID)
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
				}, nil)
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
	if dbReaction == nil {
		dbReaction = &database.Reaction{}
	}
	// Fill all fields that are known to allow omitting them in connector code
	if dbReaction.Room.ID == "" {
		dbReaction.Room = portal.PortalKey
	}
	if dbReaction.MessageID == "" {
		dbReaction.MessageID = reactionTarget.ID
		dbReaction.MessagePartID = reactionTarget.PartID
	}
	if deterministicID != "" {
		dbReaction.MXID = deterministicID
	} else if dbReaction.MXID == "" {
		dbReaction.MXID = evt.ID
	}
	if dbReaction.Timestamp.IsZero() {
		dbReaction.Timestamp = time.UnixMilli(evt.Timestamp)
	}
	if preResp.EmojiID == "" && dbReaction.EmojiID == "" {
		if dbReaction.Emoji == "" {
			dbReaction.Emoji = preResp.Emoji
		}
	} else if dbReaction.EmojiID == "" {
		dbReaction.EmojiID = preResp.EmojiID
	}
	if dbReaction.SenderID == "" {
		dbReaction.SenderID = preResp.SenderID
	}
	if dbReaction.SenderMXID == "" {
		dbReaction.SenderMXID = evt.Sender
	}
	err = portal.Bridge.DB.Reaction.Upsert(ctx, dbReaction)
	if err != nil {
		log.Err(err).Msg("Failed to save reaction to database")
	}
	portal.sendSuccessStatus(ctx, evt, 0, deterministicID)
}

func handleMatrixRoomMeta[APIType any, ContentType any](
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
			portal.sendSuccessStatus(ctx, evt, 0, "")
			return
		}
	case *event.TopicEventContent:
		if typedContent.Topic == portal.Topic {
			portal.sendSuccessStatus(ctx, evt, 0, "")
			return
		}
	case *event.RoomAvatarEventContent:
		if typedContent.URL == portal.AvatarMXC {
			portal.sendSuccessStatus(ctx, evt, 0, "")
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

			InputTransactionID: portal.parseInputTransactionID(origSender, evt),
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
	portal.sendSuccessStatus(ctx, evt, 0, "")
}

func handleMatrixAccountData[APIType any, ContentType any](
	portal *Portal, ctx context.Context, sender *UserLogin, evt *event.Event,
	fn func(APIType, context.Context, *MatrixRoomMeta[ContentType]) error,
) {
	api, ok := sender.Client.(APIType)
	if !ok {
		return
	}
	log := zerolog.Ctx(ctx)
	content, ok := evt.Content.Parsed.(ContentType)
	if !ok {
		log.Error().Type("content_type", evt.Content.Parsed).Msg("Unexpected parsed content type")
		return
	}
	var prevContent ContentType
	if evt.Unsigned.PrevContent != nil {
		_ = evt.Unsigned.PrevContent.ParseRaw(evt.Type)
		prevContent, _ = evt.Unsigned.PrevContent.Parsed.(ContentType)
	}

	err := fn(api, ctx, &MatrixRoomMeta[ContentType]{
		MatrixEventBase: MatrixEventBase[ContentType]{
			Event:   evt,
			Content: content,
			Portal:  portal,
		},
		PrevContent: prevContent,
	})
	if err != nil {
		log.Err(err).Msg("Failed to handle Matrix room account data")
	}
}

func (portal *Portal) getTargetUser(ctx context.Context, userID id.UserID) (GhostOrUserLogin, error) {
	if targetGhost, err := portal.Bridge.GetGhostByMXID(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to get ghost: %w", err)
	} else if targetGhost != nil {
		return targetGhost, nil
	} else if targetUser, err := portal.Bridge.GetUserByMXID(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	} else if targetUserLogin, _, err := portal.FindPreferredLogin(ctx, targetUser, false); err != nil {
		return nil, fmt.Errorf("failed to find preferred login: %w", err)
	} else if targetUserLogin != nil {
		return targetUserLogin, nil
	} else {
		// Return raw nil as a separate case to ensure a typed nil isn't returned
		return nil, nil
	}
}

func (portal *Portal) handleMatrixMembership(
	ctx context.Context,
	sender *UserLogin,
	origSender *OrigSender,
	evt *event.Event,
) {
	log := zerolog.Ctx(ctx)
	content, ok := evt.Content.Parsed.(*event.MemberEventContent)
	if !ok {
		log.Error().Type("content_type", evt.Content.Parsed).Msg("Unexpected parsed content type")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: %T", ErrUnexpectedParsedContentType, evt.Content.Parsed))
		return
	}
	prevContent := &event.MemberEventContent{Membership: event.MembershipLeave}
	if evt.Unsigned.PrevContent != nil {
		_ = evt.Unsigned.PrevContent.ParseRaw(evt.Type)
		prevContent, _ = evt.Unsigned.PrevContent.Parsed.(*event.MemberEventContent)
	}
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.
			Str("membership", string(content.Membership)).
			Str("prev_membership", string(prevContent.Membership)).
			Str("target_user_id", evt.GetStateKey())
	})
	api, ok := sender.Client.(MembershipHandlingNetworkAPI)
	if !ok {
		portal.sendErrorStatus(ctx, evt, ErrMembershipNotSupported)
		return
	}
	targetMXID := id.UserID(*evt.StateKey)
	isSelf := sender.User.MXID == targetMXID
	target, err := portal.getTargetUser(ctx, targetMXID)
	if err != nil {
		log.Err(err).Msg("Failed to get member event target")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}

	membershipChangeType := MembershipChangeType{From: prevContent.Membership, To: content.Membership, IsSelf: isSelf}
	if !portal.Bridge.Config.BridgeMatrixLeave && membershipChangeType == Leave {
		log.Debug().Msg("Dropping leave event")
		//portal.sendErrorStatus(ctx, evt, ErrIgnoringLeaveEvent)
		return
	}
	targetGhost, _ := target.(*Ghost)
	targetUserLogin, _ := target.(*UserLogin)
	membershipChange := &MatrixMembershipChange{
		MatrixRoomMeta: MatrixRoomMeta[*event.MemberEventContent]{
			MatrixEventBase: MatrixEventBase[*event.MemberEventContent]{
				Event:      evt,
				Content:    content,
				Portal:     portal,
				OrigSender: origSender,

				InputTransactionID: portal.parseInputTransactionID(origSender, evt),
			},
			PrevContent: prevContent,
		},
		Target:          target,
		TargetGhost:     targetGhost,
		TargetUserLogin: targetUserLogin,
		Type:            membershipChangeType,
	}
	_, err = api.HandleMatrixMembership(ctx, membershipChange)
	if err != nil {
		log.Err(err).Msg("Failed to handle Matrix membership change")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}
}

func makePLChange(old, new int, newIsSet bool) *SinglePowerLevelChange {
	if old == new {
		return nil
	}
	return &SinglePowerLevelChange{OrigLevel: old, NewLevel: new, NewIsSet: newIsSet}
}

func getUniqueKeys[Key comparable, Value any](maps ...map[Key]Value) map[Key]struct{} {
	unique := make(map[Key]struct{})
	for _, m := range maps {
		for k := range m {
			unique[k] = struct{}{}
		}
	}
	return unique
}

func (portal *Portal) handleMatrixPowerLevels(
	ctx context.Context,
	sender *UserLogin,
	origSender *OrigSender,
	evt *event.Event,
) {
	log := zerolog.Ctx(ctx)
	content, ok := evt.Content.Parsed.(*event.PowerLevelsEventContent)
	if !ok {
		log.Error().Type("content_type", evt.Content.Parsed).Msg("Unexpected parsed content type")
		portal.sendErrorStatus(ctx, evt, fmt.Errorf("%w: %T", ErrUnexpectedParsedContentType, evt.Content.Parsed))
		return
	}
	api, ok := sender.Client.(PowerLevelHandlingNetworkAPI)
	if !ok {
		portal.sendErrorStatus(ctx, evt, ErrPowerLevelsNotSupported)
		return
	}
	prevContent := &event.PowerLevelsEventContent{}
	if evt.Unsigned.PrevContent != nil {
		_ = evt.Unsigned.PrevContent.ParseRaw(evt.Type)
		prevContent, _ = evt.Unsigned.PrevContent.Parsed.(*event.PowerLevelsEventContent)
	}

	plChange := &MatrixPowerLevelChange{
		MatrixRoomMeta: MatrixRoomMeta[*event.PowerLevelsEventContent]{
			MatrixEventBase: MatrixEventBase[*event.PowerLevelsEventContent]{
				Event:      evt,
				Content:    content,
				Portal:     portal,
				OrigSender: origSender,

				InputTransactionID: portal.parseInputTransactionID(origSender, evt),
			},
			PrevContent: prevContent,
		},
		Users:         make(map[id.UserID]*UserPowerLevelChange),
		Events:        make(map[string]*SinglePowerLevelChange),
		UsersDefault:  makePLChange(prevContent.UsersDefault, content.UsersDefault, true),
		EventsDefault: makePLChange(prevContent.EventsDefault, content.EventsDefault, true),
		StateDefault:  makePLChange(prevContent.StateDefault(), content.StateDefault(), content.StateDefaultPtr != nil),
		Invite:        makePLChange(prevContent.Invite(), content.Invite(), content.InvitePtr != nil),
		Kick:          makePLChange(prevContent.Kick(), content.Kick(), content.KickPtr != nil),
		Ban:           makePLChange(prevContent.Ban(), content.Ban(), content.BanPtr != nil),
		Redact:        makePLChange(prevContent.Redact(), content.Redact(), content.RedactPtr != nil),
	}
	for eventType := range getUniqueKeys(content.Events, prevContent.Events) {
		newLevel, hasNewLevel := content.Events[eventType]
		if !hasNewLevel {
			// TODO this doesn't handle state events properly
			newLevel = content.EventsDefault
		}
		if change := makePLChange(prevContent.Events[eventType], newLevel, hasNewLevel); change != nil {
			plChange.Events[eventType] = change
		}
	}
	for user := range getUniqueKeys(content.Users, prevContent.Users) {
		_, hasNewLevel := content.Users[user]
		change := makePLChange(prevContent.GetUserLevel(user), content.GetUserLevel(user), hasNewLevel)
		if change == nil {
			continue
		}
		target, err := portal.getTargetUser(ctx, user)
		if err != nil {
			log.Err(err).Stringer("target_user_id", user).Msg("Failed to get user for power level change")
		} else {
			plChange.Users[user] = &UserPowerLevelChange{
				Target:                 target,
				SinglePowerLevelChange: *change,
			}
		}
	}
	_, err := api.HandleMatrixPowerLevels(ctx, plChange)
	if err != nil {
		log.Err(err).Msg("Failed to handle Matrix power level change")
		portal.sendErrorStatus(ctx, evt, err)
		return
	}
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

				InputTransactionID: portal.parseInputTransactionID(origSender, evt),
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

				InputTransactionID: portal.parseInputTransactionID(origSender, evt),
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
	portal.sendSuccessStatus(ctx, evt, 0, "")
}

func (portal *Portal) handleRemoteEvent(ctx context.Context, source *UserLogin, evtType RemoteEventType, evt RemoteEvent) {
	log := zerolog.Ctx(ctx)
	if portal.MXID == "" {
		mcp, ok := evt.(RemoteEventThatMayCreatePortal)
		if !ok || !mcp.ShouldCreatePortal() {
			log.Debug().Msg("Dropping event as portal doesn't exist")
			return
		}
		infoProvider, ok := mcp.(RemoteChatResyncWithInfo)
		var info *ChatInfo
		var err error
		if ok {
			info, err = infoProvider.GetChatInfo(ctx, portal)
			if err != nil {
				log.Err(err).Msg("Failed to get chat info for portal creation from chat resync event")
			}
		}
		bundleProvider, ok := evt.(RemoteChatResyncBackfillBundle)
		var bundle any
		if ok {
			bundle = bundleProvider.GetBundledBackfillData()
		}
		err = portal.createMatrixRoomInLoop(ctx, source, info, bundle)
		if err != nil {
			log.Err(err).Msg("Failed to create portal to handle event")
			// TODO error
			return
		}
		if evtType == RemoteEventChatResync {
			log.Debug().Msg("Not handling chat resync event further as portal was created by it")
			postHandler, ok := evt.(RemotePostHandler)
			if ok {
				postHandler.PostHandle(ctx, portal)
			}
			return
		}
	}
	preHandler, ok := evt.(RemotePreHandler)
	if ok {
		preHandler.PreHandle(ctx, portal)
	}
	log.Debug().Msg("Handling remote event")
	switch evtType {
	case RemoteEventUnknown:
		log.Debug().Msg("Ignoring remote event with type unknown")
	case RemoteEventMessage, RemoteEventMessageUpsert:
		portal.handleRemoteMessage(ctx, source, evt.(RemoteMessage))
	case RemoteEventEdit:
		portal.handleRemoteEdit(ctx, source, evt.(RemoteEdit))
	case RemoteEventReaction:
		portal.handleRemoteReaction(ctx, source, evt.(RemoteReaction))
	case RemoteEventReactionRemove:
		portal.handleRemoteReactionRemove(ctx, source, evt.(RemoteReactionRemove))
	case RemoteEventReactionSync:
		portal.handleRemoteReactionSync(ctx, source, evt.(RemoteReactionSync))
	case RemoteEventMessageRemove:
		portal.handleRemoteMessageRemove(ctx, source, evt.(RemoteMessageRemove))
	case RemoteEventReadReceipt:
		portal.handleRemoteReadReceipt(ctx, source, evt.(RemoteReadReceipt))
	case RemoteEventMarkUnread:
		portal.handleRemoteMarkUnread(ctx, source, evt.(RemoteMarkUnread))
	case RemoteEventDeliveryReceipt:
		portal.handleRemoteDeliveryReceipt(ctx, source, evt.(RemoteDeliveryReceipt))
	case RemoteEventTyping:
		portal.handleRemoteTyping(ctx, source, evt.(RemoteTyping))
	case RemoteEventChatInfoChange:
		portal.handleRemoteChatInfoChange(ctx, source, evt.(RemoteChatInfoChange))
	case RemoteEventChatResync:
		portal.handleRemoteChatResync(ctx, source, evt.(RemoteChatResync))
	case RemoteEventChatDelete:
		portal.handleRemoteChatDelete(ctx, source, evt.(RemoteChatDelete))
	case RemoteEventBackfill:
		portal.handleRemoteBackfill(ctx, source, evt.(RemoteBackfill))
	default:
		log.Warn().Msg("Got remote event with unknown type")
	}
	postHandler, ok := evt.(RemotePostHandler)
	if ok {
		postHandler.PostHandle(ctx, portal)
	}
}

func (portal *Portal) getIntentAndUserMXIDFor(ctx context.Context, sender EventSender, source *UserLogin, otherLogins []*UserLogin, evtType RemoteEventType) (intent MatrixAPI, extraUserID id.UserID) {
	var ghost *Ghost
	if !sender.IsFromMe && sender.ForceDMUser && portal.OtherUserID != "" && sender.Sender != portal.OtherUserID {
		zerolog.Ctx(ctx).Warn().
			Str("original_id", string(sender.Sender)).
			Str("default_other_user", string(portal.OtherUserID)).
			Msg("Overriding event sender with primary other user in DM portal")
		// Ensure the ghost row exists anyway to prevent foreign key errors when saving messages
		// TODO it'd probably be better to override the sender in the saved message, but that's more effort
		_, err := portal.Bridge.GetGhostByID(ctx, sender.Sender)
		if err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).Msg("Failed to get ghost with original user ID")
		}
		sender.Sender = portal.OtherUserID
	}
	if sender.Sender != "" {
		var err error
		ghost, err = portal.Bridge.GetGhostByID(ctx, sender.Sender)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get ghost for message sender")
			return
		} else {
			ghost.UpdateInfoIfNecessary(ctx, source, evtType)
		}
	}
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
	if sender.Sender != "" && portal.Receiver == "" && otherLogins != nil {
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
	if ghost != nil {
		intent = ghost.Intent
	}
	return
}

func (portal *Portal) GetIntentFor(ctx context.Context, sender EventSender, source *UserLogin, evtType RemoteEventType) MatrixAPI {
	intent, _ := portal.getIntentAndUserMXIDFor(ctx, sender, source, nil, evtType)
	if intent == nil {
		// TODO this is very hacky - we should either insert an empty ghost row automatically
		//      (and not fetch it at runtime) or make the message sender column nullable.
		portal.Bridge.GetGhostByID(ctx, "")
		intent = portal.Bridge.Bot
	}
	return intent
}

func (portal *Portal) getRelationMeta(ctx context.Context, currentMsg networkid.MessageID, replyToPtr *networkid.MessageOptionalPartID, threadRootPtr *networkid.MessageID, isBatchSend bool) (replyTo, threadRoot, prevThreadEvent *database.Message) {
	log := zerolog.Ctx(ctx)
	var err error
	if replyToPtr != nil {
		replyTo, err = portal.Bridge.DB.Message.GetFirstOrSpecificPartByID(ctx, portal.Receiver, *replyToPtr)
		if err != nil {
			log.Err(err).Msg("Failed to get reply target message from database")
		} else if replyTo == nil {
			if isBatchSend || portal.Bridge.Config.OutgoingMessageReID {
				// This is somewhat evil
				replyTo = &database.Message{
					MXID: portal.Bridge.Matrix.GenerateDeterministicEventID(portal.MXID, portal.PortalKey, replyToPtr.MessageID, ptr.Val(replyToPtr.PartID)),
				}
			} else {
				log.Warn().Any("reply_to", *replyToPtr).Msg("Reply target message not found in database")
			}
		}
	}
	if threadRootPtr != nil && *threadRootPtr != currentMsg {
		threadRoot, err = portal.Bridge.DB.Message.GetFirstThreadMessage(ctx, portal.PortalKey, *threadRootPtr)
		if err != nil {
			log.Err(err).Msg("Failed to get thread root message from database")
		} else if threadRoot == nil {
			if isBatchSend || portal.Bridge.Config.OutgoingMessageReID {
				threadRoot = &database.Message{
					MXID: portal.Bridge.Matrix.GenerateDeterministicEventID(portal.MXID, portal.PortalKey, *threadRootPtr, ""),
				}
			} else {
				log.Warn().Str("thread_root", string(*threadRootPtr)).Msg("Thread root message not found in database")
			}
		} else if prevThreadEvent, err = portal.Bridge.DB.Message.GetLastThreadMessage(ctx, portal.PortalKey, *threadRootPtr); err != nil {
			log.Err(err).Msg("Failed to get last thread message from database")
		}
		if prevThreadEvent == nil {
			prevThreadEvent = threadRoot
		}
	}
	return
}

func (portal *Portal) applyRelationMeta(ctx context.Context, content *event.MessageEventContent, replyTo, threadRoot, prevThreadEvent *database.Message) {
	if content.Mentions == nil {
		content.Mentions = &event.Mentions{}
	}
	if threadRoot != nil && prevThreadEvent != nil {
		content.GetRelatesTo().SetThread(threadRoot.MXID, prevThreadEvent.MXID)
	}
	if replyTo != nil {
		crossRoom := replyTo.Room != portal.PortalKey
		if !crossRoom || portal.Bridge.Config.CrossRoomReplies {
			content.GetRelatesTo().SetReplyTo(replyTo.MXID)
		}
		if crossRoom && portal.Bridge.Config.CrossRoomReplies {
			targetPortal, err := portal.Bridge.GetExistingPortalByKey(ctx, replyTo.Room)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).
					Object("target_portal_key", replyTo.Room).
					Msg("Failed to get cross-room reply portal")
			} else if targetPortal == nil || targetPortal.MXID == "" {
				zerolog.Ctx(ctx).Warn().
					Object("target_portal_key", replyTo.Room).
					Msg("Cross-room reply portal not found")
			} else {
				content.RelatesTo.InReplyTo.UnstableRoomID = targetPortal.MXID
			}
		}
		content.Mentions.Add(replyTo.SenderMXID)
	}
}

func (portal *Portal) sendConvertedMessage(
	ctx context.Context,
	id networkid.MessageID,
	intent MatrixAPI,
	senderID networkid.UserID,
	converted *ConvertedMessage,
	ts time.Time,
	streamOrder int64,
	logContext func(*zerolog.Event) *zerolog.Event,
) []*database.Message {
	if logContext == nil {
		logContext = func(e *zerolog.Event) *zerolog.Event {
			return e
		}
	}
	log := zerolog.Ctx(ctx)
	replyTo, threadRoot, prevThreadEvent := portal.getRelationMeta(ctx, id, converted.ReplyTo, converted.ThreadRoot, false)
	output := make([]*database.Message, 0, len(converted.Parts))
	for i, part := range converted.Parts {
		portal.applyRelationMeta(ctx, part.Content, replyTo, threadRoot, prevThreadEvent)
		dbMessage := &database.Message{
			ID:               id,
			PartID:           part.ID,
			Room:             portal.PortalKey,
			SenderID:         senderID,
			SenderMXID:       intent.GetMXID(),
			Timestamp:        ts,
			ThreadRoot:       ptr.Val(converted.ThreadRoot),
			ReplyTo:          ptr.Val(converted.ReplyTo),
			Metadata:         part.DBMetadata,
			IsDoublePuppeted: intent.IsDoublePuppet(),
		}
		if part.DontBridge {
			dbMessage.SetFakeMXID()
			logContext(log.Debug()).
				Stringer("event_id", dbMessage.MXID).
				Str("part_id", string(part.ID)).
				Msg("Not bridging message part with DontBridge flag to Matrix")
		} else {
			resp, err := intent.SendMessage(ctx, portal.MXID, part.Type, &event.Content{
				Parsed: part.Content,
				Raw:    part.Extra,
			}, &MatrixSendExtra{
				Timestamp:   ts,
				MessageMeta: dbMessage,
				StreamOrder: streamOrder,
				PartIndex:   i,
			})
			if err != nil {
				logContext(log.Err(err)).Str("part_id", string(part.ID)).Msg("Failed to send message part to Matrix")
				continue
			}
			logContext(log.Debug()).
				Stringer("event_id", resp.EventID).
				Str("part_id", string(part.ID)).
				Msg("Sent message part to Matrix")
			dbMessage.MXID = resp.EventID
		}
		err := portal.Bridge.DB.Message.Insert(ctx, dbMessage)
		if err != nil {
			logContext(log.Err(err)).Str("part_id", string(part.ID)).Msg("Failed to save message part to database")
		}
		if converted.Disappear.Type != database.DisappearingTypeNone && !dbMessage.HasFakeMXID() {
			if converted.Disappear.Type == database.DisappearingTypeAfterSend && converted.Disappear.DisappearAt.IsZero() {
				converted.Disappear.DisappearAt = dbMessage.Timestamp.Add(converted.Disappear.Timer)
			}
			go portal.Bridge.DisappearLoop.Add(ctx, &database.DisappearingMessage{
				RoomID:              portal.MXID,
				EventID:             dbMessage.MXID,
				DisappearingSetting: converted.Disappear,
			})
		}
		if prevThreadEvent != nil && !dbMessage.HasFakeMXID() {
			prevThreadEvent = dbMessage
		}
		output = append(output, dbMessage)
	}
	return output
}

func (portal *Portal) checkPendingMessage(ctx context.Context, evt RemoteMessage) (bool, *database.Message) {
	evtWithTxn, ok := evt.(RemoteMessageWithTransactionID)
	if !ok {
		return false, nil
	}
	txnID := evtWithTxn.GetTransactionID()
	if txnID == "" {
		return false, nil
	}
	portal.outgoingMessagesLock.Lock()
	defer portal.outgoingMessagesLock.Unlock()
	pending, ok := portal.outgoingMessages[txnID]
	if !ok {
		return false, nil
	} else if pending.ignore {
		return true, nil
	}
	delete(portal.outgoingMessages, txnID)
	pending.db.ID = evt.GetID()
	if pending.db.SenderID == "" {
		pending.db.SenderID = evt.GetSender().Sender
	}
	evtWithTimestamp, ok := evt.(RemoteEventWithTimestamp)
	if ok {
		ts := evtWithTimestamp.GetTimestamp()
		if !ts.IsZero() {
			pending.db.Timestamp = ts
		}
	}
	var statusErr error
	saveMessage := true
	if pending.handle != nil {
		saveMessage, statusErr = pending.handle(evt, pending.db)
	}
	if saveMessage {
		if portal.Bridge.Config.OutgoingMessageReID {
			pending.db.MXID = portal.Bridge.Matrix.GenerateDeterministicEventID(portal.MXID, portal.PortalKey, pending.db.ID, pending.db.PartID)
		}
		// Hack to ensure the ghost row exists
		// TODO move to better place (like login)
		portal.Bridge.GetGhostByID(ctx, pending.db.SenderID)
		err := portal.Bridge.DB.Message.Insert(ctx, pending.db)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to save message to database after receiving remote echo")
		}
	}
	if !errors.Is(statusErr, ErrNoStatus) {
		if statusErr != nil {
			portal.sendErrorStatus(ctx, pending.evt, statusErr)
		} else {
			portal.sendSuccessStatus(ctx, pending.evt, getStreamOrder(evt), pending.evt.ID)
		}
	}
	zerolog.Ctx(ctx).Debug().Stringer("event_id", pending.evt.ID).Msg("Received remote echo for message")
	return true, pending.db
}

func (portal *Portal) handleRemoteUpsert(ctx context.Context, source *UserLogin, evt RemoteMessageUpsert, existing []*database.Message) bool {
	log := zerolog.Ctx(ctx)
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventMessageUpsert)
	if intent == nil {
		return false
	}
	res, err := evt.HandleExisting(ctx, portal, intent, existing)
	if err != nil {
		log.Err(err).Msg("Failed to handle existing message in upsert event after receiving remote echo")
	}
	if res.SaveParts {
		for _, part := range existing {
			err = portal.Bridge.DB.Message.Update(ctx, part)
			if err != nil {
				log.Err(err).Str("part_id", string(part.PartID)).Msg("Failed to update message part in database")
			}
		}
	}
	if len(res.SubEvents) > 0 {
		for _, subEvt := range res.SubEvents {
			subType := subEvt.GetType()
			log := portal.Log.With().
				Str("source_id", string(source.ID)).
				Str("action", "handle remote subevent").
				Stringer("bridge_evt_type", subType).
				Logger()
			portal.handleRemoteEvent(log.WithContext(ctx), source, subType, subEvt)
		}
	}
	return res.ContinueMessageHandling
}

func (portal *Portal) handleRemoteMessage(ctx context.Context, source *UserLogin, evt RemoteMessage) {
	log := zerolog.Ctx(ctx)
	upsertEvt, isUpsert := evt.(RemoteMessageUpsert)
	isUpsert = isUpsert && evt.GetType() == RemoteEventMessageUpsert
	if wasPending, dbMessage := portal.checkPendingMessage(ctx, evt); wasPending {
		if isUpsert && dbMessage != nil {
			portal.handleRemoteUpsert(ctx, source, upsertEvt, []*database.Message{dbMessage})
		}
		return
	}
	existing, err := portal.Bridge.DB.Message.GetAllPartsByID(ctx, portal.Receiver, evt.GetID())
	if err != nil {
		log.Err(err).Msg("Failed to check if message is a duplicate")
	} else if len(existing) > 0 {
		if isUpsert {
			if portal.handleRemoteUpsert(ctx, source, upsertEvt, existing) {
				log.Debug().Msg("Upsert handler said to continue message handling normally")
			} else {
				return
			}
		} else {
			log.Debug().Stringer("existing_mxid", existing[0].MXID).Msg("Ignoring duplicate message")
			return
		}
	}
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventMessage)
	if intent == nil {
		return
	}
	ts := getEventTS(evt)
	converted, err := evt.ConvertMessage(ctx, portal, intent)
	if err != nil {
		if errors.Is(err, ErrIgnoringRemoteEvent) {
			log.Debug().Err(err).Msg("Remote message handling was cancelled by convert function")
		} else {
			log.Err(err).Msg("Failed to convert remote message")
			portal.sendRemoteErrorNotice(ctx, intent, err, ts, "message")
		}
		return
	}
	portal.sendConvertedMessage(ctx, evt.GetID(), intent, evt.GetSender().Sender, converted, ts, getStreamOrder(evt), nil)
	if portal.currentlyTypingGhosts.Pop(intent.GetMXID()) {
		intent.MarkTyping(ctx, portal.MXID, TypingTypeText, 0)
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
	}, &MatrixSendExtra{
		Timestamp: ts,
	})
	if sendErr != nil {
		zerolog.Ctx(ctx).Err(sendErr).Msg("Failed to send error notice after remote event handling failed")
	} else {
		zerolog.Ctx(ctx).Debug().Stringer("event_id", resp.EventID).Msg("Sent error notice after remote event handling failed")
	}
}

func (portal *Portal) handleRemoteEdit(ctx context.Context, source *UserLogin, evt RemoteEdit) {
	log := zerolog.Ctx(ctx)
	var existing []*database.Message
	if bundledEvt, ok := evt.(RemoteEventWithBundledParts); ok {
		existing = bundledEvt.GetTargetDBMessage()
	}
	if existing == nil {
		targetID := evt.GetTargetMessage()
		var err error
		existing, err = portal.Bridge.DB.Message.GetAllPartsByID(ctx, portal.Receiver, targetID)
		if err != nil {
			log.Err(err).Msg("Failed to get edit target message")
			return
		}
	}
	if existing == nil {
		log.Warn().Msg("Edit target message not found")
		return
	}
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventEdit)
	if intent == nil {
		return
	} else if intent.GetMXID() != existing[0].SenderMXID {
		log.Warn().
			Stringer("edit_sender_mxid", intent.GetMXID()).
			Stringer("original_sender_mxid", existing[0].SenderMXID).
			Msg("Not bridging edit: sender doesn't match original message sender")
		return
	}
	ts := getEventTS(evt)
	converted, err := evt.ConvertEdit(ctx, portal, intent, existing)
	if errors.Is(err, ErrIgnoringRemoteEvent) {
		log.Debug().Err(err).Msg("Remote edit handling was cancelled by convert function")
		return
	} else if err != nil {
		log.Err(err).Msg("Failed to convert remote edit")
		portal.sendRemoteErrorNotice(ctx, intent, err, ts, "edit")
		return
	}
	portal.sendConvertedEdit(ctx, existing[0].ID, evt.GetSender().Sender, converted, intent, ts, getStreamOrder(evt))
	if portal.currentlyTypingGhosts.Pop(intent.GetMXID()) {
		intent.MarkTyping(ctx, portal.MXID, TypingTypeText, 0)
	}
}

func (portal *Portal) sendConvertedEdit(
	ctx context.Context,
	targetID networkid.MessageID,
	senderID networkid.UserID,
	converted *ConvertedEdit,
	intent MatrixAPI,
	ts time.Time,
	streamOrder int64,
) {
	log := zerolog.Ctx(ctx)
	for i, part := range converted.ModifiedParts {
		if part.Content.Mentions == nil {
			part.Content.Mentions = &event.Mentions{}
		}
		overrideMXID := true
		if part.Part.Room != portal.PortalKey {
			part.Part.Room = portal.PortalKey
		} else if !part.Part.HasFakeMXID() {
			part.Content.SetEdit(part.Part.MXID)
			overrideMXID = false
			if part.NewMentions != nil {
				part.Content.Mentions = part.NewMentions
			} else {
				part.Content.Mentions = &event.Mentions{}
			}
		}
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
		if !part.DontBridge {
			resp, err := intent.SendMessage(ctx, portal.MXID, part.Type, wrappedContent, &MatrixSendExtra{
				Timestamp:   ts,
				MessageMeta: part.Part,
				StreamOrder: streamOrder,
				PartIndex:   i,
			})
			if err != nil {
				log.Err(err).Stringer("part_mxid", part.Part.MXID).Msg("Failed to edit message part")
				continue
			} else {
				log.Debug().
					Stringer("event_id", resp.EventID).
					Str("part_id", string(part.Part.ID)).
					Msg("Sent message part edit to Matrix")
				if overrideMXID {
					part.Part.MXID = resp.EventID
				}
			}
		}
		err := portal.Bridge.DB.Message.Update(ctx, part.Part)
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
		resp, err := intent.SendMessage(ctx, portal.MXID, event.EventRedaction, redactContent, &MatrixSendExtra{
			Timestamp: ts,
		})
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
	if converted.AddedParts != nil {
		portal.sendConvertedMessage(ctx, targetID, intent, senderID, converted.AddedParts, ts, streamOrder, nil)
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
		return portal.Bridge.DB.Reaction.GetByID(ctx, portal.Receiver, evt.GetTargetMessage(), partTargeter.GetTargetMessagePart(), evt.GetSender().Sender, evt.GetRemovedEmojiID())
	} else {
		return portal.Bridge.DB.Reaction.GetByIDWithoutMessagePart(ctx, portal.Receiver, evt.GetTargetMessage(), evt.GetSender().Sender, evt.GetRemovedEmojiID())
	}
}

func getEventTS(evt RemoteEvent) time.Time {
	if tsProvider, ok := evt.(RemoteEventWithTimestamp); ok {
		return tsProvider.GetTimestamp()
	}
	return time.Now()
}

func getStreamOrder(evt RemoteEvent) int64 {
	if streamProvider, ok := evt.(RemoteEventWithStreamOrder); ok {
		return streamProvider.GetStreamOrder()
	}
	return 0
}

func (portal *Portal) handleRemoteReactionSync(ctx context.Context, source *UserLogin, evt RemoteReactionSync) {
	log := zerolog.Ctx(ctx)
	eventTS := getEventTS(evt)
	targetMessage, err := portal.getTargetMessagePart(ctx, evt)
	if err != nil {
		log.Err(err).Msg("Failed to get target message for reaction")
		return
	} else if targetMessage == nil {
		// TODO use deterministic event ID as target if applicable?
		log.Warn().Msg("Target message for reaction not found")
		return
	}
	var existingReactions []*database.Reaction
	if partTargeter, ok := evt.(RemoteEventWithTargetPart); ok {
		existingReactions, err = portal.Bridge.DB.Reaction.GetAllToMessagePart(ctx, portal.Receiver, evt.GetTargetMessage(), partTargeter.GetTargetMessagePart())
	} else {
		existingReactions, err = portal.Bridge.DB.Reaction.GetAllToMessage(ctx, portal.Receiver, evt.GetTargetMessage())
	}
	existing := make(map[networkid.UserID]map[networkid.EmojiID]*database.Reaction)
	for _, existingReaction := range existingReactions {
		if existing[existingReaction.SenderID] == nil {
			existing[existingReaction.SenderID] = make(map[networkid.EmojiID]*database.Reaction)
		}
		existing[existingReaction.SenderID][existingReaction.EmojiID] = existingReaction
	}

	doAddReaction := func(new *BackfillReaction, intent MatrixAPI) MatrixAPI {
		if intent == nil {
			intent = portal.GetIntentFor(ctx, new.Sender, source, RemoteEventReactionSync)
		}
		portal.sendConvertedReaction(
			ctx, new.Sender.Sender, intent, targetMessage, new.EmojiID, new.Emoji,
			new.Timestamp, new.DBMetadata, new.ExtraContent,
			func(z *zerolog.Event) *zerolog.Event {
				return z.
					Any("reaction_sender_id", new.Sender).
					Time("reaction_ts", new.Timestamp)
			},
		)
		return intent
	}
	doRemoveReaction := func(old *database.Reaction, intent MatrixAPI, deleteRow bool) {
		if intent == nil && old.SenderMXID != "" {
			intent, err = portal.getIntentForMXID(ctx, old.SenderMXID)
			if err != nil {
				log.Err(err).
					Stringer("reaction_sender_mxid", old.SenderMXID).
					Msg("Failed to get intent for removing reaction")
			}
		}
		if intent == nil {
			log.Warn().
				Str("reaction_sender_id", string(old.SenderID)).
				Stringer("reaction_sender_mxid", old.SenderMXID).
				Msg("Didn't find intent for removing reaction, using bridge bot")
			intent = portal.Bridge.Bot
		}
		_, err = intent.SendMessage(ctx, portal.MXID, event.EventRedaction, &event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: old.MXID,
			},
		}, &MatrixSendExtra{Timestamp: eventTS})
		if err != nil {
			log.Err(err).Msg("Failed to redact old reaction")
		}
		if deleteRow {
			err = portal.Bridge.DB.Reaction.Delete(ctx, old)
			if err != nil {
				log.Err(err).Msg("Failed to delete old reaction row")
			}
		}
	}
	doOverwriteReaction := func(new *BackfillReaction, old *database.Reaction) {
		intent := portal.GetIntentFor(ctx, new.Sender, source, RemoteEventReactionSync)
		doRemoveReaction(old, intent, false)
		doAddReaction(new, intent)
	}

	newData := evt.GetReactions()
	for userID, reactions := range newData.Users {
		existingUserReactions := existing[userID]
		delete(existing, userID)
		for _, reaction := range reactions.Reactions {
			if reaction.Timestamp.IsZero() {
				reaction.Timestamp = eventTS
			}
			existingReaction, ok := existingUserReactions[reaction.EmojiID]
			if ok {
				delete(existingUserReactions, reaction.EmojiID)
				if reaction.EmojiID != "" || reaction.Emoji == existingReaction.Emoji {
					continue
				}
				doOverwriteReaction(reaction, existingReaction)
			} else {
				doAddReaction(reaction, nil)
			}
		}
		totalReactionCount := len(existingUserReactions) + len(reactions.Reactions)
		if reactions.HasAllReactions {
			for _, existingReaction := range existingUserReactions {
				doRemoveReaction(existingReaction, nil, true)
			}
		} else if reactions.MaxCount > 0 && totalReactionCount > reactions.MaxCount {
			remainingReactionList := maps.Values(existingUserReactions)
			slices.SortFunc(remainingReactionList, func(a, b *database.Reaction) int {
				diff := a.Timestamp.Compare(b.Timestamp)
				if diff == 0 {
					return cmp.Compare(a.EmojiID, b.EmojiID)
				}
				return diff
			})
			numberToRemove := totalReactionCount - reactions.MaxCount
			for i := 0; i < numberToRemove && i < len(remainingReactionList); i++ {
				doRemoveReaction(remainingReactionList[i], nil, true)
			}
		}
	}
	if newData.HasAllUsers {
		for _, userReactions := range existing {
			for _, existingReaction := range userReactions {
				doRemoveReaction(existingReaction, nil, true)
			}
		}
	}
}

func (portal *Portal) handleRemoteReaction(ctx context.Context, source *UserLogin, evt RemoteReaction) {
	log := zerolog.Ctx(ctx)
	targetMessage, err := portal.getTargetMessagePart(ctx, evt)
	if err != nil {
		log.Err(err).Msg("Failed to get target message for reaction")
		return
	} else if targetMessage == nil {
		// TODO use deterministic event ID as target if applicable?
		log.Warn().Msg("Target message for reaction not found")
		return
	}
	emoji, emojiID := evt.GetReactionEmoji()
	existingReaction, err := portal.Bridge.DB.Reaction.GetByID(ctx, portal.Receiver, targetMessage.ID, targetMessage.PartID, evt.GetSender().Sender, emojiID)
	if err != nil {
		log.Err(err).Msg("Failed to check if reaction is a duplicate")
		return
	} else if existingReaction != nil && (emojiID != "" || existingReaction.Emoji == emoji) {
		log.Debug().Msg("Ignoring duplicate reaction")
		return
	}
	ts := getEventTS(evt)
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventReaction)
	var extra map[string]any
	if extraContentProvider, ok := evt.(RemoteReactionWithExtraContent); ok {
		extra = extraContentProvider.GetReactionExtraContent()
	}
	var dbMetadata any
	if metaProvider, ok := evt.(RemoteReactionWithMeta); ok {
		dbMetadata = metaProvider.GetReactionDBMetadata()
	}
	if existingReaction != nil {
		_, err = intent.SendMessage(ctx, portal.MXID, event.EventRedaction, &event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: existingReaction.MXID,
			},
		}, &MatrixSendExtra{Timestamp: ts})
		if err != nil {
			log.Err(err).Msg("Failed to redact old reaction")
		}
	}
	portal.sendConvertedReaction(ctx, evt.GetSender().Sender, intent, targetMessage, emojiID, emoji, ts, dbMetadata, extra, nil)
}

func (portal *Portal) sendConvertedReaction(
	ctx context.Context, senderID networkid.UserID, intent MatrixAPI, targetMessage *database.Message,
	emojiID networkid.EmojiID, emoji string, ts time.Time, dbMetadata any, extraContent map[string]any,
	logContext func(*zerolog.Event) *zerolog.Event,
) {
	if logContext == nil {
		logContext = func(e *zerolog.Event) *zerolog.Event {
			return e
		}
	}
	log := zerolog.Ctx(ctx)
	dbReaction := &database.Reaction{
		Room:          portal.PortalKey,
		MessageID:     targetMessage.ID,
		MessagePartID: targetMessage.PartID,
		SenderID:      senderID,
		SenderMXID:    intent.GetMXID(),
		EmojiID:       emojiID,
		Timestamp:     ts,
		Metadata:      dbMetadata,
	}
	if emojiID == "" {
		dbReaction.Emoji = emoji
	}
	resp, err := intent.SendMessage(ctx, portal.MXID, event.EventReaction, &event.Content{
		Parsed: &event.ReactionEventContent{
			RelatesTo: event.RelatesTo{
				Type:    event.RelAnnotation,
				EventID: targetMessage.MXID,
				Key:     variationselector.Add(emoji),
			},
		},
		Raw: extraContent,
	}, &MatrixSendExtra{
		Timestamp:    ts,
		ReactionMeta: dbReaction,
	})
	if err != nil {
		logContext(log.Err(err)).Msg("Failed to send reaction to Matrix")
		return
	}
	logContext(log.Debug()).
		Stringer("event_id", resp.EventID).
		Msg("Sent reaction to Matrix")
	dbReaction.MXID = resp.EventID
	err = portal.Bridge.DB.Reaction.Upsert(ctx, dbReaction)
	if err != nil {
		logContext(log.Err(err)).Msg("Failed to save reaction to database")
	}
}

func (portal *Portal) getIntentForMXID(ctx context.Context, userID id.UserID) (MatrixAPI, error) {
	if userID == "" {
		return nil, nil
	} else if ghost, err := portal.Bridge.GetGhostByMXID(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to get ghost: %w", err)
	} else if ghost != nil {
		return ghost.Intent, nil
	} else if user, err := portal.Bridge.GetExistingUserByMXID(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	} else if user != nil {
		return user.DoublePuppet(ctx), nil
	} else {
		return nil, nil
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
	intent, err := portal.getIntentForMXID(ctx, targetReaction.SenderMXID)
	if err != nil {
		log.Err(err).Stringer("sender_mxid", targetReaction.SenderMXID).Msg("Failed to get intent for removing reaction")
	}
	if intent == nil {
		intent = portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventReactionRemove)
	}
	ts := getEventTS(evt)
	_, err = intent.SendMessage(ctx, portal.MXID, event.EventRedaction, &event.Content{
		Parsed: &event.RedactionEventContent{
			Redacts: targetReaction.MXID,
		},
	}, &MatrixSendExtra{Timestamp: ts, ReactionMeta: targetReaction})
	if err != nil {
		log.Err(err).Stringer("reaction_mxid", targetReaction.MXID).Msg("Failed to redact reaction")
	}
	err = portal.Bridge.DB.Reaction.Delete(ctx, targetReaction)
	if err != nil {
		log.Err(err).Msg("Failed to delete target reaction from database")
	}
}

func (portal *Portal) handleRemoteMessageRemove(ctx context.Context, source *UserLogin, evt RemoteMessageRemove) {
	editInstedOfDelete := portal.Bridge.Config.EditInsteadOfDelete

	log := zerolog.Ctx(ctx)
	targetParts, err := portal.Bridge.DB.Message.GetAllPartsByID(ctx, portal.Receiver, evt.GetTargetMessage())
	if err != nil {
		log.Err(err).Msg("Failed to get target message for removal")
		return
	} else if len(targetParts) == 0 {
		log.Debug().Msg("Target message not found")
		return
	}
	if editInstedOfDelete {
		portal.editMessageToIndicateDeletion(ctx, targetParts, getEventTS(evt), getStreamOrder(evt), source)
		return
	}
	onlyForMeProvider, ok := evt.(RemoteDeleteOnlyForMe)
	onlyForMe := ok && onlyForMeProvider.DeleteOnlyForMe()
	if onlyForMe && portal.Receiver == "" {
		// TODO check if there are other user logins before deleting
	}

	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventMessageRemove)
	if intent == portal.Bridge.Bot && len(targetParts) > 0 {
		senderIntent, err := portal.getIntentForMXID(ctx, targetParts[0].SenderMXID)
		if err != nil {
			log.Err(err).Stringer("sender_mxid", targetParts[0].SenderMXID).Msg("Failed to get intent for removing message")
		} else if senderIntent != nil {
			intent = senderIntent
		}
	}
	portal.redactMessageParts(ctx, targetParts, intent, getEventTS(evt))
	err = portal.Bridge.DB.Message.DeleteAllParts(ctx, portal.Receiver, evt.GetTargetMessage())
	if err != nil {
		log.Err(err).Msg("Failed to delete target message from database")
	}
}
func (portal *Portal) editMessageToIndicateDeletion(ctx context.Context, targetParts []*database.Message, ts time.Time, streamOrder int64, source *UserLogin) {
	log := zerolog.Ctx(ctx)
	intent := portal.GetIntentFor(ctx, EventSender{Sender: targetParts[0].SenderID}, source, RemoteEventMessageRemove)
	if intent == nil {
		log.Warn().Msg("No intent found for editing message to indicate deletion")
		return
	}

	for i, part := range targetParts {
		if part.HasFakeMXID() {
			continue
		}

		// Create the edited content
		editedContent := &event.MessageEventContent{
			MsgType: event.MsgNotice,
			Body:    "This message has been deleted.",
			Mentions: &event.Mentions{
				UserIDs: []id.UserID{},
			},
		}
		rawContent := map[string]interface{}{
			"msgtype": event.MsgNotice,
			"body":    "* This message has been deleted.",
			"m.new_content": map[string]interface{}{
				"body":       "This message has been deleted.",
				"msgtype":    event.MsgNotice,
				"m.mentions": "{}",
			},
			"m.relates_to": map[string]interface{}{
				"rel_type": event.RelReplace,
				"event_id": part.MXID,
			},
		}
		editedContent.SetEdit(part.MXID)
		// Send the edit event to Matrix
		_, err := intent.SendMessage(ctx, portal.MXID, event.EventMessage, &event.Content{
			Parsed: editedContent,
			Raw:    rawContent,
		}, &MatrixSendExtra{
			Timestamp:   ts,
			MessageMeta: part,
			StreamOrder: streamOrder,
			PartIndex:   i,
		})
		if err != nil {
			log.Err(err).Stringer("part_mxid", part.MXID).Msg("Failed to edit message to indicate deletion")
		} else {
			log.Debug().
				Stringer("part_mxid", part.MXID).
				Msg("Edited message to indicate deletion")
		}

		// Update the database to reflect the edited message
		part.Metadata = "deleted"
		err = portal.Bridge.DB.Message.Update(ctx, part)
		if err != nil {
			log.Err(err).Int64("part_rowid", part.RowID).Msg("Failed to update message part in database")
		}
	}
}
func (portal *Portal) redactMessageParts(ctx context.Context, parts []*database.Message, intent MatrixAPI, ts time.Time) {
	log := zerolog.Ctx(ctx)
	for _, part := range parts {
		if part.HasFakeMXID() {
			continue
		}
		resp, err := intent.SendMessage(ctx, portal.MXID, event.EventRedaction, &event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: part.MXID,
			},
		}, &MatrixSendExtra{Timestamp: ts, MessageMeta: part})
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
}

func (portal *Portal) handleRemoteReadReceipt(ctx context.Context, source *UserLogin, evt RemoteReadReceipt) {
	log := zerolog.Ctx(ctx)
	var err error
	var lastTarget *database.Message
	readUpTo := evt.GetReadUpTo()
	if lastTargetID := evt.GetLastReceiptTarget(); lastTargetID != "" {
		lastTarget, err = portal.Bridge.DB.Message.GetLastPartByID(ctx, portal.Receiver, lastTargetID)
		if err != nil {
			log.Err(err).Str("last_target_id", string(lastTargetID)).
				Msg("Failed to get last target message for read receipt")
			return
		} else if lastTarget == nil {
			log.Debug().Str("last_target_id", string(lastTargetID)).
				Msg("Last target message not found")
		} else if lastTarget.HasFakeMXID() {
			log.Debug().Str("last_target_id", string(lastTargetID)).
				Msg("Last target message is fake")
			if readUpTo.IsZero() {
				readUpTo = lastTarget.Timestamp
			}
			lastTarget = nil
		}
	}
	if lastTarget == nil {
		for _, targetID := range evt.GetReceiptTargets() {
			target, err := portal.Bridge.DB.Message.GetLastPartByID(ctx, portal.Receiver, targetID)
			if err != nil {
				log.Err(err).Str("target_id", string(targetID)).
					Msg("Failed to get target message for read receipt")
				return
			} else if target != nil && !target.HasFakeMXID() && (lastTarget == nil || target.Timestamp.After(lastTarget.Timestamp)) {
				lastTarget = target
			}
		}
	}
	if lastTarget == nil && !readUpTo.IsZero() {
		lastTarget, err = portal.Bridge.DB.Message.GetLastNonFakePartAtOrBeforeTime(ctx, portal.PortalKey, readUpTo)
		if err != nil {
			log.Err(err).Time("read_up_to", readUpTo).Msg("Failed to get target message for read receipt")
		}
	}
	sender := evt.GetSender()
	intent := portal.GetIntentFor(ctx, sender, source, RemoteEventReadReceipt)
	var addTargetLog func(evt *zerolog.Event) *zerolog.Event
	if lastTarget == nil {
		sevt, evtOK := evt.(RemoteReadReceiptWithStreamOrder)
		soIntent, soIntentOK := intent.(StreamOrderReadingMatrixAPI)
		if !evtOK || !soIntentOK || sevt.GetReadUpToStreamOrder() == 0 {
			log.Warn().Msg("No target message found for read receipt")
			return
		}
		targetStreamOrder := sevt.GetReadUpToStreamOrder()
		addTargetLog = func(evt *zerolog.Event) *zerolog.Event {
			return evt.Int64("target_stream_order", targetStreamOrder)
		}
		err = soIntent.MarkStreamOrderRead(ctx, portal.MXID, targetStreamOrder, getEventTS(evt))
	} else {
		addTargetLog = func(evt *zerolog.Event) *zerolog.Event {
			return evt.Stringer("target_mxid", lastTarget.MXID)
		}
		err = intent.MarkRead(ctx, portal.MXID, lastTarget.MXID, getEventTS(evt))
	}
	if err != nil {
		addTargetLog(log.Err(err)).Msg("Failed to bridge read receipt")
	} else {
		addTargetLog(log.Debug()).Msg("Bridged read receipt")
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

func (portal *Portal) handleRemoteDeliveryReceipt(ctx context.Context, source *UserLogin, evt RemoteDeliveryReceipt) {
	if portal.RoomType != database.RoomTypeDM || evt.GetSender().Sender != portal.OtherUserID {
		return
	}
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventDeliveryReceipt)
	log := zerolog.Ctx(ctx)
	for _, target := range evt.GetReceiptTargets() {
		targetParts, err := portal.Bridge.DB.Message.GetAllPartsByID(ctx, portal.Receiver, target)
		if err != nil {
			log.Err(err).Str("target_id", string(target)).Msg("Failed to get target message for delivery receipt")
			continue
		} else if len(targetParts) == 0 {
			continue
		} else if _, sentByGhost := portal.Bridge.Matrix.ParseGhostMXID(targetParts[0].SenderMXID); sentByGhost {
			continue
		}
		for _, part := range targetParts {
			portal.Bridge.Matrix.SendMessageStatus(ctx, &MessageStatus{
				Status:      event.MessageStatusSuccess,
				DeliveredTo: []id.UserID{intent.GetMXID()},
			}, &MessageStatusEventInfo{
				RoomID:        portal.MXID,
				SourceEventID: part.MXID,
				Sender:        part.SenderMXID,

				IsSourceEventDoublePuppeted: part.IsDoublePuppeted,
			})
		}
	}
}

func (portal *Portal) handleRemoteTyping(ctx context.Context, source *UserLogin, evt RemoteTyping) {
	var typingType TypingType
	if typedEvt, ok := evt.(RemoteTypingWithType); ok {
		typingType = typedEvt.GetTypingType()
	}
	intent := portal.GetIntentFor(ctx, evt.GetSender(), source, RemoteEventTyping)
	timeout := evt.GetTimeout()
	err := intent.MarkTyping(ctx, portal.MXID, typingType, timeout)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to bridge typing event")
	}
	if timeout == 0 {
		portal.currentlyTypingGhosts.Remove(intent.GetMXID())
	} else {
		portal.currentlyTypingGhosts.Add(intent.GetMXID())
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

func (portal *Portal) handleRemoteChatResync(ctx context.Context, source *UserLogin, evt RemoteChatResync) {
	log := zerolog.Ctx(ctx)
	infoProvider, ok := evt.(RemoteChatResyncWithInfo)
	if ok {
		info, err := infoProvider.GetChatInfo(ctx, portal)
		if err != nil {
			log.Err(err).Msg("Failed to get chat info from resync event")
		} else if info != nil {
			portal.UpdateInfo(ctx, info, source, nil, time.Time{})
		} else {
			log.Debug().Msg("No chat info provided in resync event")
		}
	}
	backfillChecker, ok := evt.(RemoteChatResyncBackfill)
	if portal.Bridge.Config.Backfill.Enabled && ok && portal.RoomType != database.RoomTypeSpace {
		latestMessage, err := portal.Bridge.DB.Message.GetLastPartAtOrBeforeTime(ctx, portal.PortalKey, time.Now().Add(10*time.Second))
		if err != nil {
			log.Err(err).Msg("Failed to get last message in portal to check if backfill is necessary")
		} else if needsBackfill, err := backfillChecker.CheckNeedsBackfill(ctx, latestMessage); err != nil {
			log.Err(err).Msg("Failed to check if backfill is needed")
		} else if needsBackfill {
			bundleProvider, ok := evt.(RemoteChatResyncBackfillBundle)
			var bundle any
			if ok {
				bundle = bundleProvider.GetBundledBackfillData()
			}
			portal.doForwardBackfill(ctx, source, latestMessage, bundle)
		}
	}
}

func (portal *Portal) handleRemoteChatDelete(ctx context.Context, source *UserLogin, evt RemoteChatDelete) {
	log := zerolog.Ctx(ctx)
	if portal.Receiver == "" && evt.DeleteOnlyForMe() {
		logins, err := portal.Bridge.DB.UserPortal.GetAllInPortal(ctx, portal.PortalKey)
		if err != nil {
			log.Err(err).Msg("Failed to check if portal has other logins")
			return
		}
		var ownUP *database.UserPortal
		logins = slices.DeleteFunc(logins, func(up *database.UserPortal) bool {
			if up.LoginID == source.ID {
				ownUP = up
				return true
			}
			return false
		})
		if len(logins) > 0 {
			log.Debug().Msg("Not deleting portal with other logins in remote chat delete event")
			if ownUP != nil {
				err = portal.Bridge.DB.UserPortal.Delete(ctx, ownUP)
				if err != nil {
					log.Err(err).Msg("Failed to delete own user portal row from database")
				} else {
					log.Debug().Msg("Deleted own user portal row from database")
				}
			}
			_, err = portal.sendStateWithIntentOrBot(
				ctx,
				source.User.DoublePuppet(ctx),
				event.StateMember,
				source.UserMXID.String(),
				&event.Content{Parsed: &event.MemberEventContent{Membership: event.MembershipLeave}},
				getEventTS(evt),
			)
			if err != nil {
				log.Err(err).Msg("Failed to send leave state event for user after remote chat delete")
			} else {
				log.Debug().Msg("Sent leave state event for user after remote chat delete")
			}
			return
		}
	}
	err := portal.Delete(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to delete portal from database")
		return
	}
	err = portal.Bridge.Bot.DeleteRoom(ctx, portal.MXID, false)
	if err != nil {
		log.Err(err).Msg("Failed to delete Matrix room")
	} else {
		log.Info().Msg("Deleted room after remote chat delete event")
	}
}

func (portal *Portal) handleRemoteBackfill(ctx context.Context, source *UserLogin, backfill RemoteBackfill) {
	//data, err := backfill.GetBackfillData(ctx, portal)
	//if err != nil {
	//	zerolog.Ctx(ctx).Err(err).Msg("Failed to get backfill data")
	//	return
	//}
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
		err := portal.syncParticipants(ctx, change.MemberChanges, source, intent, ts)
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
	Nickname   *string
	PowerLevel *int
	UserInfo   *UserInfo

	MemberEventExtra map[string]any
	PrevMembership   event.Membership
}

type ChatMemberList struct {
	// Whether this is the full member list.
	// If true, any extra members not listed here will be removed from the portal.
	IsFull bool
	// Should the bridge call IsThisUser for every member in the list?
	// This should be used when SenderLogin can't be filled accurately.
	CheckAllLogins bool

	// The total number of members in the chat, regardless of how many of those members are included in MemberMap.
	TotalMemberCount int

	// For DM portals, the ID of the recipient user.
	// This field is optional and will be automatically filled from MemberMap if there are only 2 entries in the map.
	OtherUserID networkid.UserID

	// Deprecated: Use MemberMap instead to avoid duplicate entries
	Members     []ChatMember
	MemberMap   map[networkid.UserID]ChatMember
	PowerLevels *PowerLevelOverrides
}

func (cml *ChatMemberList) memberListToMap(ctx context.Context) {
	if cml.Members == nil || cml.MemberMap != nil {
		return
	}
	cml.MemberMap = make(map[networkid.UserID]ChatMember, len(cml.Members))
	for _, member := range cml.Members {
		if _, alreadyExists := cml.MemberMap[member.Sender]; alreadyExists {
			zerolog.Ctx(ctx).Warn().Str("member_id", string(member.Sender)).Msg("Duplicate member in list")
		}
		cml.MemberMap[member.Sender] = member
	}
}

type PowerLevelOverrides struct {
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

// Deprecated: renamed to PowerLevelOverrides
type PowerLevelChanges = PowerLevelOverrides

func allowChange(newLevel *int, oldLevel, actorLevel int) bool {
	return newLevel != nil &&
		*newLevel <= actorLevel && oldLevel <= actorLevel &&
		oldLevel != *newLevel
}

func (plc *PowerLevelOverrides) Apply(actor id.UserID, content *event.PowerLevelsEventContent) (changed bool) {
	if plc == nil || content == nil {
		return
	}
	for evtType, level := range plc.Events {
		changed = content.EnsureEventLevelAs(actor, evtType, level) || changed
	}
	var actorLevel int
	if actor != "" {
		actorLevel = content.GetUserLevel(actor)
	} else {
		actorLevel = (1 << 31) - 1
	}
	if allowChange(plc.UsersDefault, content.UsersDefault, actorLevel) {
		changed = true
		content.UsersDefault = *plc.UsersDefault
	}
	if allowChange(plc.EventsDefault, content.EventsDefault, actorLevel) {
		changed = true
		content.EventsDefault = *plc.EventsDefault
	}
	if allowChange(plc.StateDefault, content.StateDefault(), actorLevel) {
		changed = true
		content.StateDefaultPtr = plc.StateDefault
	}
	if allowChange(plc.Invite, content.Invite(), actorLevel) {
		changed = true
		content.InvitePtr = plc.Invite
	}
	if allowChange(plc.Kick, content.Kick(), actorLevel) {
		changed = true
		content.KickPtr = plc.Kick
	}
	if allowChange(plc.Ban, content.Ban(), actorLevel) {
		changed = true
		content.BanPtr = plc.Ban
	}
	if allowChange(plc.Redact, content.Redact(), actorLevel) {
		changed = true
		content.RedactPtr = plc.Redact
	}
	if plc.Custom != nil {
		changed = plc.Custom(content) || changed
	}
	return changed
}

// DefaultChatName can be used to explicitly clear the name of a room
// and reset it to the default one based on members.
var DefaultChatName = ptr.Ptr("")

type ChatInfo struct {
	Name   *string
	Topic  *string
	Avatar *Avatar

	Members  *ChatMemberList
	JoinRule *event.JoinRulesEventContent

	Type      *database.RoomType
	Disappear *database.DisappearingSetting
	ParentID  *networkid.PortalID

	UserLocal *UserLocalPortalInfo

	CanBackfill bool

	ExtraUpdates ExtraUpdater[*Portal]
}

type ExtraUpdater[T any] func(context.Context, T) bool

func MergeExtraUpdaters[T any](funcs ...ExtraUpdater[T]) ExtraUpdater[T] {
	funcs = slices.DeleteFunc(funcs, func(f ExtraUpdater[T]) bool {
		return f == nil
	})
	if len(funcs) == 0 {
		return nil
	} else if len(funcs) == 1 {
		return funcs[0]
	}
	return func(ctx context.Context, p T) bool {
		changed := false
		for _, f := range funcs {
			changed = f(ctx, p) || changed
		}
		return changed
	}
}

var Unmuted = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

type UserLocalPortalInfo struct {
	// To signal an indefinite mute, use [event.MutedForever] as the value here.
	// To unmute, set any time before now, e.g. [bridgev2.Unmuted].
	MutedUntil *time.Time
	Tag        *event.RoomTag
}

func (portal *Portal) updateName(ctx context.Context, name string, sender MatrixAPI, ts time.Time) bool {
	if portal.Name == name && (portal.NameSet || portal.MXID == "") {
		return false
	}
	portal.Name = name
	portal.NameSet = portal.sendRoomMeta(ctx, sender, ts, event.StateRoomName, "", &event.RoomNameEventContent{Name: name})
	return true
}

func (portal *Portal) updateTopic(ctx context.Context, topic string, sender MatrixAPI, ts time.Time) bool {
	if portal.Topic == topic && (portal.TopicSet || portal.MXID == "") {
		return false
	}
	portal.Topic = topic
	portal.TopicSet = portal.sendRoomMeta(ctx, sender, ts, event.StateTopic, "", &event.TopicEventContent{Topic: topic})
	return true
}

func (portal *Portal) updateAvatar(ctx context.Context, avatar *Avatar, sender MatrixAPI, ts time.Time) bool {
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
		newMXC, newHash, err := avatar.Reupload(ctx, sender, portal.AvatarHash, portal.AvatarMXC)
		if err != nil {
			portal.AvatarSet = false
			zerolog.Ctx(ctx).Err(err).Msg("Failed to reupload room avatar")
			return true
		} else if newHash == portal.AvatarHash && portal.AvatarSet {
			return true
		}
		portal.AvatarMXC = newMXC
		portal.AvatarHash = newHash
	}
	portal.AvatarSet = portal.sendRoomMeta(ctx, sender, ts, event.StateRoomAvatar, "", &event.RoomAvatarEventContent{URL: portal.AvatarMXC})
	return true
}

func (portal *Portal) GetTopLevelParent() *Portal {
	if portal.Parent == nil {
		if portal.RoomType != database.RoomTypeSpace {
			return nil
		}
		return portal
	}
	return portal.Parent.GetTopLevelParent()
}

func (portal *Portal) getBridgeInfoStateKey() string {
	if portal.Bridge.Config.NoBridgeInfoStateKey {
		return ""
	}
	idProvider, ok := portal.Bridge.Matrix.(MatrixConnectorWithBridgeIdentifier)
	if ok {
		return idProvider.GetUniqueBridgeID()
	}
	return string(portal.BridgeID)
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
			Receiver:    string(portal.Receiver),
			// TODO external URL?
		},
		BeeperRoomTypeV2: string(portal.RoomType),
	}
	if portal.RoomType == database.RoomTypeDM || portal.RoomType == database.RoomTypeGroupDM {
		bridgeInfo.BeeperRoomType = "dm"
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
	filler, ok := portal.Bridge.Network.(PortalBridgeInfoFillingNetwork)
	if ok {
		filler.FillPortalBridgeInfo(portal, &bridgeInfo)
	}
	return portal.getBridgeInfoStateKey(), bridgeInfo
}

func (portal *Portal) UpdateBridgeInfo(ctx context.Context) {
	if portal.MXID == "" {
		return
	}
	stateKey, bridgeInfo := portal.getBridgeInfo()
	portal.sendRoomMeta(ctx, nil, time.Now(), event.StateBridge, stateKey, &bridgeInfo)
	portal.sendRoomMeta(ctx, nil, time.Now(), event.StateHalfShotBridge, stateKey, &bridgeInfo)
}

func (portal *Portal) UpdateCapabilities(ctx context.Context, source *UserLogin, implicit bool) bool {
	if portal.MXID == "" {
		return false
	} else if !implicit && time.Since(portal.lastCapUpdate) < 24*time.Hour {
		return false
	} else if portal.CapState.ID != "" && source.ID != portal.CapState.Source && source.ID != portal.Receiver {
		// TODO allow capability state source to change if the old user login is removed from the portal
		return false
	}
	caps := source.Client.GetCapabilities(ctx, portal)
	capID := caps.GetID()
	if capID == portal.CapState.ID {
		return false
	}
	zerolog.Ctx(ctx).Debug().
		Str("user_login_id", string(source.ID)).
		Str("old_id", portal.CapState.ID).
		Str("new_id", capID).
		Msg("Sending new room capability event")
	success := portal.sendRoomMeta(ctx, nil, time.Now(), event.StateBeeperRoomFeatures, portal.getBridgeInfoStateKey(), caps)
	if !success {
		return false
	}
	portal.CapState = database.CapabilityState{
		Source: source.ID,
		ID:     capID,
	}
	portal.lastCapUpdate = time.Now()
	if implicit {
		err := portal.Save(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to save portal capability state after sending state event")
		}
	}
	return true
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
		resp, err = portal.Bridge.Bot.SendState(ctx, portal.MXID, eventType, stateKey, content, ts)
	}
	return
}

func (portal *Portal) sendRoomMeta(ctx context.Context, sender MatrixAPI, ts time.Time, eventType event.Type, stateKey string, content any) bool {
	if portal.MXID == "" {
		return false
	}
	var extra map[string]any
	if !portal.NameIsCustom && (eventType == event.StateRoomName || eventType == event.StateRoomAvatar) {
		extra = map[string]any{
			"fi.mau.implicit_name": true,
		}
	}
	_, err := portal.sendStateWithIntentOrBot(ctx, sender, eventType, stateKey, &event.Content{
		Parsed: content,
		Raw:    extra,
	}, ts)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Str("event_type", eventType.Type).
			Msg("Failed to set room metadata")
		return false
	}
	return true
}

func (portal *Portal) getInitialMemberList(ctx context.Context, members *ChatMemberList, source *UserLogin, pl *event.PowerLevelsEventContent) (invite, functional []id.UserID, err error) {
	if members == nil {
		invite = []id.UserID{source.UserMXID}
		return
	}
	var loginsInPortal []*UserLogin
	if members.CheckAllLogins && !portal.Bridge.Config.SplitPortals {
		loginsInPortal, err = portal.Bridge.GetUserLoginsInPortal(ctx, portal.PortalKey)
		if err != nil {
			err = fmt.Errorf("failed to get user logins in portal: %w", err)
			return
		}
	}
	members.PowerLevels.Apply("", pl)
	members.memberListToMap(ctx)
	for _, member := range members.MemberMap {
		if ctx.Err() != nil {
			err = ctx.Err()
			return
		}
		if member.Membership != event.MembershipJoin && member.Membership != "" {
			continue
		}
		if member.Sender != "" && member.UserInfo != nil {
			ghost, err := portal.Bridge.GetGhostByID(ctx, member.Sender)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Str("ghost_id", string(member.Sender)).Msg("Failed to get ghost from member list to update info")
			} else {
				ghost.UpdateInfo(ctx, member.UserInfo)
			}
		}
		intent, extraUserID := portal.getIntentAndUserMXIDFor(ctx, member.EventSender, source, loginsInPortal, 0)
		if extraUserID != "" {
			invite = append(invite, extraUserID)
			if member.PowerLevel != nil {
				pl.EnsureUserLevel(extraUserID, *member.PowerLevel)
			}
			if intent != nil {
				// If intent is present along with a user ID, it's the ghost of a logged-in user,
				// so add it to the functional members list
				functional = append(functional, intent.GetMXID())
			}
		}
		if intent != nil {
			invite = append(invite, intent.GetMXID())
			if member.PowerLevel != nil {
				pl.EnsureUserLevel(intent.GetMXID(), *member.PowerLevel)
			}
		}
	}
	portal.updateOtherUser(ctx, members)
	return
}

func (portal *Portal) updateOtherUser(ctx context.Context, members *ChatMemberList) (changed bool) {
	members.memberListToMap(ctx)
	var expectedUserID networkid.UserID
	if portal.RoomType != database.RoomTypeDM {
		// expected user ID is empty
	} else if members.OtherUserID != "" {
		expectedUserID = members.OtherUserID
	} else if len(members.MemberMap) == 2 && members.IsFull {
		vals := maps.Values(members.MemberMap)
		if vals[0].IsFromMe && !vals[1].IsFromMe {
			expectedUserID = vals[1].Sender
		} else if vals[1].IsFromMe && !vals[0].IsFromMe {
			expectedUserID = vals[0].Sender
		}
	}
	if portal.OtherUserID != expectedUserID {
		zerolog.Ctx(ctx).Debug().
			Str("old_other_user_id", string(portal.OtherUserID)).
			Str("new_other_user_id", string(expectedUserID)).
			Msg("Updating other user ID in DM portal")
		portal.OtherUserID = expectedUserID
		return true
	}
	return false
}

func (portal *Portal) syncParticipants(
	ctx context.Context,
	members *ChatMemberList,
	source *UserLogin,
	sender MatrixAPI,
	ts time.Time,
) error {
	members.memberListToMap(ctx)
	var loginsInPortal []*UserLogin
	var err error
	if members.CheckAllLogins && !portal.Bridge.Config.SplitPortals {
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
	powerChanged := members.PowerLevels.Apply(portal.Bridge.Bot.GetMXID(), currentPower)
	syncUser := func(extraUserID id.UserID, member ChatMember, intent MatrixAPI) bool {
		if member.Membership == "" {
			member.Membership = event.MembershipJoin
		}
		if member.PowerLevel != nil {
			powerChanged = currentPower.EnsureUserLevelAs(portal.Bridge.Bot.GetMXID(), extraUserID, *member.PowerLevel) || powerChanged
		}
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
		wrappedContent := &event.Content{Parsed: content, Raw: maps.Clone(member.MemberEventExtra)}
		if wrappedContent.Raw == nil {
			wrappedContent.Raw = make(map[string]any)
		}
		thisEvtSender := sender
		if member.Membership == event.MembershipJoin {
			content.Membership = event.MembershipInvite
			if intent != nil {
				wrappedContent.Raw["fi.mau.will_auto_accept"] = true
			}
			if thisEvtSender.GetMXID() == extraUserID {
				thisEvtSender = portal.Bridge.Bot
			}
		}
		addLogContext := func(e *zerolog.Event) *zerolog.Event {
			return e.Stringer("target_user_id", extraUserID).
				Stringer("sender_user_id", thisEvtSender.GetMXID()).
				Str("prev_membership", string(currentMember.Membership))
		}
		if currentMember != nil && currentMember.Membership == event.MembershipBan && member.Membership != event.MembershipLeave {
			unbanContent := *content
			unbanContent.Membership = event.MembershipLeave
			wrappedUnbanContent := &event.Content{Parsed: &unbanContent}
			_, err = portal.sendStateWithIntentOrBot(ctx, thisEvtSender, event.StateMember, extraUserID.String(), wrappedUnbanContent, ts)
			if err != nil {
				addLogContext(log.Err(err)).
					Str("new_membership", string(unbanContent.Membership)).
					Msg("Failed to unban user to update membership")
			} else {
				addLogContext(log.Trace()).
					Str("new_membership", string(unbanContent.Membership)).
					Msg("Unbanned user to update membership")
				currentMember.Membership = event.MembershipLeave
			}
		}
		_, err = portal.sendStateWithIntentOrBot(ctx, thisEvtSender, event.StateMember, extraUserID.String(), wrappedContent, ts)
		if err != nil {
			addLogContext(log.Err(err)).
				Str("new_membership", string(content.Membership)).
				Msg("Failed to update user membership")
		} else {
			addLogContext(log.Trace()).
				Str("new_membership", string(content.Membership)).
				Msg("Updated membership in room")
			currentMember.Membership = content.Membership

			if intent != nil && content.Membership == event.MembershipInvite && member.Membership == event.MembershipJoin {
				content.Membership = event.MembershipJoin
				wrappedJoinContent := &event.Content{Parsed: content, Raw: member.MemberEventExtra}
				_, err = intent.SendState(ctx, portal.MXID, event.StateMember, intent.GetMXID().String(), wrappedJoinContent, ts)
				if err != nil {
					addLogContext(log.Err(err)).
						Str("new_membership", string(content.Membership)).
						Msg("Failed to join with intent")
				} else {
					addLogContext(log.Trace()).
						Str("new_membership", string(content.Membership)).
						Msg("Joined room with intent")
				}
			}
		}
		return true
	}
	syncIntent := func(intent MatrixAPI, member ChatMember) {
		if !syncUser(intent.GetMXID(), member, intent) {
			return
		}
		if member.Membership == event.MembershipJoin || member.Membership == "" {
			err = intent.EnsureJoined(ctx, portal.MXID)
			if err != nil {
				log.Err(err).
					Stringer("user_id", intent.GetMXID()).
					Msg("Failed to ensure user is joined to room")
			}
		}
	}
	for _, member := range members.MemberMap {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if member.Sender != "" && member.UserInfo != nil {
			ghost, err := portal.Bridge.GetGhostByID(ctx, member.Sender)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Str("ghost_id", string(member.Sender)).Msg("Failed to get ghost from member list to update info")
			} else {
				ghost.UpdateInfo(ctx, member.UserInfo)
			}
		}
		intent, extraUserID := portal.getIntentAndUserMXIDFor(ctx, member.EventSender, source, loginsInPortal, 0)
		if intent != nil {
			syncIntent(intent, member)
		}
		if extraUserID != "" {
			syncUser(extraUserID, member, nil)
		}
	}
	if powerChanged {
		_, err = portal.sendStateWithIntentOrBot(ctx, sender, event.StatePowerLevels, "", &event.Content{Parsed: currentPower}, ts)
		if err != nil {
			log.Err(err).Msg("Failed to update power levels")
		}
	}
	portal.updateOtherUser(ctx, members)
	if members.IsFull {
		for extraMember, memberEvt := range currentMembers {
			if memberEvt.Membership == event.MembershipLeave || memberEvt.Membership == event.MembershipBan {
				continue
			}
			if !portal.Bridge.IsGhostMXID(extraMember) && portal.Relay != nil {
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

func (portal *Portal) updateUserLocalInfo(ctx context.Context, info *UserLocalPortalInfo, source *UserLogin, didJustCreate bool) {
	if portal.MXID == "" {
		return
	}
	dp := source.User.DoublePuppet(ctx)
	if dp == nil {
		return
	}
	dmMarkingMatrixAPI, canMarkDM := dp.(MarkAsDMMatrixAPI)
	if canMarkDM && portal.OtherUserID != "" && portal.RoomType == database.RoomTypeDM {
		dmGhost, err := portal.Bridge.GetGhostByID(ctx, portal.OtherUserID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get DM ghost to mark room as DM")
		} else if err = dmMarkingMatrixAPI.MarkAsDM(ctx, portal.MXID, dmGhost.Intent.GetMXID()); err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to mark room as DM")
		}
	}
	if info == nil {
		return
	}
	if info.MutedUntil != nil && (didJustCreate || !portal.Bridge.Config.MuteOnlyOnCreate) && (!didJustCreate || info.MutedUntil.After(time.Now())) {
		err := dp.MuteRoom(ctx, portal.MXID, *info.MutedUntil)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to mute room")
		}
	}
	if info.Tag != nil &&
		len(portal.Bridge.Config.OnlyBridgeTags) > 0 &&
		(*info.Tag == "" || slices.Contains(portal.Bridge.Config.OnlyBridgeTags, *info.Tag)) &&
		(didJustCreate || !portal.Bridge.Config.TagOnlyOnCreate) &&
		(!didJustCreate || *info.Tag != "") {
		err := dp.TagRoom(ctx, portal.MXID, *info.Tag, *info.Tag != "")
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to tag room")
		}
	}
}

func DisappearingMessageNotice(expiration time.Duration, implicit bool) *event.MessageEventContent {
	formattedDuration := exfmt.DurationCustom(expiration, nil, exfmt.Day, time.Hour, time.Minute, time.Second)
	content := &event.MessageEventContent{
		MsgType:  event.MsgNotice,
		Body:     fmt.Sprintf("Set the disappearing message timer to %s", formattedDuration),
		Mentions: &event.Mentions{},
	}
	if implicit {
		content.Body = fmt.Sprintf("Automatically enabled disappearing message timer (%s) because incoming message is disappearing", formattedDuration)
	} else if expiration == 0 {
		content.Body = "Turned off disappearing messages"
	}
	return content
}

func (portal *Portal) UpdateDisappearingSetting(ctx context.Context, setting database.DisappearingSetting, sender MatrixAPI, ts time.Time, implicit, save bool) bool {
	if setting.Timer == 0 {
		setting.Type = ""
	}
	if portal.Disappear.Timer == setting.Timer && portal.Disappear.Type == setting.Type {
		return false
	}
	portal.Disappear.Type = setting.Type
	portal.Disappear.Timer = setting.Timer
	if save {
		err := portal.Save(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to save portal to database after updating disappearing setting")
		}
	}
	if portal.MXID == "" {
		return true
	}
	content := DisappearingMessageNotice(setting.Timer, implicit)
	if sender == nil {
		sender = portal.Bridge.Bot
	}
	_, err := sender.SendMessage(ctx, portal.MXID, event.EventMessage, &event.Content{
		Parsed: content,
	}, &MatrixSendExtra{Timestamp: ts})
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to send disappearing messages notice")
	} else {
		zerolog.Ctx(ctx).Debug().
			Dur("new_timer", portal.Disappear.Timer).
			Bool("implicit", implicit).
			Msg("Sent disappearing messages notice")
	}
	return true
}

func (portal *Portal) updateParent(ctx context.Context, newParentID networkid.PortalID, source *UserLogin) bool {
	newParent := networkid.PortalKey{ID: newParentID}
	if portal.Bridge.Config.SplitPortals {
		newParent.Receiver = portal.Receiver
	}
	if portal.ParentKey == newParent {
		return false
	}
	var err error
	if portal.MXID != "" && portal.InSpace && portal.Parent != nil && portal.Parent.MXID != "" {
		err = portal.toggleSpace(ctx, portal.Parent.MXID, false, true)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Stringer("old_space_mxid", portal.Parent.MXID).Msg("Failed to remove portal from old space")
		}
	}
	portal.ParentKey = newParent
	portal.InSpace = false
	if newParent.ID != "" {
		portal.Parent, err = portal.Bridge.GetPortalByKey(ctx, newParent)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get new parent portal")
		}
	}
	if portal.MXID != "" && portal.Parent != nil && (source != nil || portal.Parent.MXID != "") {
		if portal.Parent.MXID == "" {
			zerolog.Ctx(ctx).Info().Msg("Parent portal doesn't exist, creating")
			err = portal.Parent.CreateMatrixRoom(ctx, source, nil)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to create parent portal")
			}
		}
		if portal.Parent.MXID != "" {
			portal.addToParentSpaceAndSave(ctx, false)
		}
	}
	return true
}

func (portal *Portal) lockedUpdateInfoFromGhost(ctx context.Context, ghost *Ghost) {
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	portal.UpdateInfoFromGhost(ctx, ghost)
}

func (portal *Portal) UpdateInfoFromGhost(ctx context.Context, ghost *Ghost) (changed bool) {
	if portal.NameIsCustom || !portal.Bridge.Config.PrivateChatPortalMeta || (portal.OtherUserID == "" && ghost == nil) || portal.RoomType != database.RoomTypeDM {
		return
	}
	var err error
	if ghost == nil {
		ghost, err = portal.Bridge.GetGhostByID(ctx, portal.OtherUserID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get ghost to update info from")
			return
		}
	}
	changed = portal.updateName(ctx, ghost.Name, nil, time.Time{}) || changed
	changed = portal.updateAvatar(ctx, &Avatar{
		ID:     ghost.AvatarID,
		MXC:    ghost.AvatarMXC,
		Hash:   ghost.AvatarHash,
		Remove: ghost.AvatarID == "",
	}, nil, time.Time{}) || changed
	return
}

func (portal *Portal) UpdateInfo(ctx context.Context, info *ChatInfo, source *UserLogin, sender MatrixAPI, ts time.Time) {
	changed := false
	if info.Name == DefaultChatName {
		if portal.NameIsCustom {
			portal.NameIsCustom = false
			changed = portal.updateName(ctx, "", sender, ts) || changed
		}
	} else if info.Name != nil {
		portal.NameIsCustom = true
		changed = portal.updateName(ctx, *info.Name, sender, ts) || changed
	}
	if info.Topic != nil {
		changed = portal.updateTopic(ctx, *info.Topic, sender, ts) || changed
	}
	if info.Avatar != nil {
		portal.NameIsCustom = true
		changed = portal.updateAvatar(ctx, info.Avatar, sender, ts) || changed
	}
	if info.Disappear != nil {
		changed = portal.UpdateDisappearingSetting(ctx, *info.Disappear, sender, ts, false, false) || changed
	}
	if info.ParentID != nil {
		changed = portal.updateParent(ctx, *info.ParentID, source) || changed
	}
	if info.JoinRule != nil {
		// TODO change detection instead of spamming this every time?
		portal.sendRoomMeta(ctx, sender, ts, event.StateJoinRules, "", info.JoinRule)
	}
	if info.Type != nil && portal.RoomType != *info.Type {
		if portal.MXID != "" && (*info.Type == database.RoomTypeSpace || portal.RoomType == database.RoomTypeSpace) {
			zerolog.Ctx(ctx).Warn().
				Str("current_type", string(portal.RoomType)).
				Str("target_type", string(*info.Type)).
				Msg("Tried to change existing room type from/to space")
		} else {
			changed = true
			portal.RoomType = *info.Type
		}
	}
	if info.Members != nil && portal.MXID != "" && source != nil {
		err := portal.syncParticipants(ctx, info.Members, source, nil, time.Time{})
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to sync room members")
		}
		// TODO detect changes to functional members list?
	} else if info.Members != nil {
		portal.updateOtherUser(ctx, info.Members)
	}
	changed = portal.UpdateInfoFromGhost(ctx, nil) || changed
	if source != nil {
		source.MarkInPortal(ctx, portal)
		portal.updateUserLocalInfo(ctx, info.UserLocal, source, false)
		changed = portal.UpdateCapabilities(ctx, source, false) || changed
	}
	if info.CanBackfill && source != nil && portal.MXID != "" {
		err := portal.Bridge.DB.BackfillTask.EnsureExists(ctx, portal.PortalKey, source.ID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to ensure backfill queue task exists")
		}
		// TODO wake up backfill queue if task was just created
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

func (portal *Portal) CreateMatrixRoom(ctx context.Context, source *UserLogin, info *ChatInfo) (retErr error) {
	if portal.MXID != "" {
		if source != nil {
			source.MarkInPortal(ctx, portal)
		}
		return nil
	}
	waiter := make(chan struct{})
	closed := false
	evt := &portalCreateEvent{
		ctx:    ctx,
		source: source,
		info:   info,
		cb: func(err error) {
			retErr = err
			if !closed {
				closed = true
				close(waiter)
			}
		},
	}
	if PortalEventBuffer == 0 {
		go portal.queueEvent(ctx, evt)
	} else {
		portal.events <- evt
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waiter:
		return
	}
}

func (portal *Portal) createMatrixRoomInLoop(ctx context.Context, source *UserLogin, info *ChatInfo, backfillBundle any) error {
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	if portal.MXID != "" {
		if source != nil {
			source.MarkInPortal(ctx, portal)
		}
		return nil
	}
	log := zerolog.Ctx(ctx).With().
		Str("action", "create matrix room").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Creating Matrix room")

	var err error
	if info == nil || info.Members == nil {
		if info != nil {
			log.Warn().Msg("CreateMatrixRoom got info without members. Refetching info")
		}
		info, err = source.Client.GetChatInfo(ctx, portal)
		if err != nil {
			log.Err(err).Msg("Failed to update portal info for creation")
			return err
		}
	}

	portal.UpdateInfo(ctx, info, source, nil, time.Time{})
	if ctx.Err() != nil {
		return ctx.Err()
	}

	powerLevels := &event.PowerLevelsEventContent{
		Events: map[string]int{
			event.StateTombstone.Type:  100,
			event.StateServerACL.Type:  100,
			event.StateEncryption.Type: 100,
		},
		Users: map[id.UserID]int{
			portal.Bridge.Bot.GetMXID(): 9001,
		},
	}
	initialMembers, extraFunctionalMembers, err := portal.getInitialMemberList(ctx, info.Members, source, powerLevels)
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
		IsDirect:           portal.RoomType == database.RoomTypeDM,
		PowerLevelOverride: powerLevels,
		BeeperLocalRoomID:  portal.Bridge.Matrix.GenerateDeterministicRoomID(portal.PortalKey),
	}
	autoJoinInvites := portal.Bridge.Matrix.GetCapabilities().AutoJoinInvites
	if autoJoinInvites {
		req.BeeperInitialMembers = initialMembers
		// TODO remove this after initial_members is supported in hungryserv
		req.BeeperAutoJoinInvites = true
		req.Invite = initialMembers
	}
	if portal.RoomType == database.RoomTypeSpace {
		req.CreationContent["type"] = event.RoomTypeSpace
	}
	bridgeInfoStateKey, bridgeInfo := portal.getBridgeInfo()
	roomFeatures := source.Client.GetCapabilities(ctx, portal)
	portal.CapState = database.CapabilityState{
		Source: source.ID,
		ID:     roomFeatures.GetID(),
	}

	req.InitialState = append(req.InitialState, &event.Event{
		Type: event.StateElementFunctionalMembers,
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
	}, &event.Event{
		StateKey: &bridgeInfoStateKey,
		Type:     event.StateBeeperRoomFeatures,
		Content:  event.Content{Parsed: roomFeatures},
	})
	if req.Topic == "" {
		// Add explicit topic event if topic is empty to ensure the event is set.
		// This ensures that there won't be an extra event later if PUT /state/... is called.
		req.InitialState = append(req.InitialState, &event.Event{
			Type:    event.StateTopic,
			Content: event.Content{Parsed: &event.TopicEventContent{Topic: ""}},
		})
	}
	if portal.AvatarMXC != "" {
		req.InitialState = append(req.InitialState, &event.Event{
			Type:    event.StateRoomAvatar,
			Content: event.Content{Parsed: &event.RoomAvatarEventContent{URL: portal.AvatarMXC}},
		})
	}
	if portal.Parent != nil && portal.Parent.MXID != "" {
		req.InitialState = append(req.InitialState, &event.Event{
			StateKey: ptr.Ptr(portal.Parent.MXID.String()),
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
	if info.CanBackfill && portal.RoomType != database.RoomTypeSpace {
		err = portal.Bridge.DB.BackfillTask.Upsert(ctx, &database.BackfillTask{
			PortalKey:         portal.PortalKey,
			UserLoginID:       source.ID,
			NextDispatchMinTS: time.Now().Add(BackfillMinBackoffAfterRoomCreate),
		})
		if err != nil {
			log.Err(err).Msg("Failed to create backfill queue task after creating room")
		}
		portal.Bridge.WakeupBackfillQueue()
	}
	withoutCancelCtx := zerolog.Ctx(ctx).WithContext(portal.Bridge.BackgroundCtx)
	if portal.Parent != nil {
		if portal.Parent.MXID != "" {
			portal.addToParentSpaceAndSave(ctx, true)
		} else {
			log.Info().Msg("Parent portal doesn't exist, creating in background")
			go portal.createParentAndAddToSpace(withoutCancelCtx, source)
		}
	}
	portal.updateUserLocalInfo(ctx, info.UserLocal, source, true)
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
			err = portal.syncParticipants(ctx, info.Members, source, nil, time.Time{})
			if err != nil {
				log.Err(err).Msg("Failed to sync participants after room creation")
			}
		}
	}
	if portal.Parent == nil {
		if portal.Receiver != "" {
			login := portal.Bridge.GetCachedUserLoginByID(portal.Receiver)
			if login != nil {
				up, err := portal.Bridge.DB.UserPortal.Get(ctx, login.UserLogin, portal.PortalKey)
				if err != nil {
					log.Err(err).Msg("Failed to get user portal to add portal to spaces")
				} else {
					login.inPortalCache.Remove(portal.PortalKey)
					go login.tryAddPortalToSpace(withoutCancelCtx, portal, up.CopyWithoutValues())
				}
			}
		} else {
			userPortals, err := portal.Bridge.DB.UserPortal.GetAllInPortal(ctx, portal.PortalKey)
			if err != nil {
				log.Err(err).Msg("Failed to get user logins in portal to add portal to spaces")
			} else {
				for _, up := range userPortals {
					login := portal.Bridge.GetCachedUserLoginByID(up.LoginID)
					if login != nil {
						login.inPortalCache.Remove(portal.PortalKey)
						go login.tryAddPortalToSpace(withoutCancelCtx, portal, up.CopyWithoutValues())
					}
				}
			}
		}
	}
	if portal.Bridge.Config.Backfill.Enabled && portal.RoomType != database.RoomTypeSpace && !portal.Bridge.Background {
		portal.doForwardBackfill(ctx, source, nil, backfillBundle)
	}
	return nil
}

func (portal *Portal) Delete(ctx context.Context) error {
	portal.removeInPortalCache(ctx)
	err := portal.Bridge.DB.Portal.Delete(ctx, portal.PortalKey)
	if err != nil {
		return err
	}
	portal.Bridge.cacheLock.Lock()
	defer portal.Bridge.cacheLock.Unlock()
	portal.unlockedDeleteCache()
	return nil
}

func (portal *Portal) RemoveMXID(ctx context.Context) error {
	if portal.MXID == "" {
		return nil
	}
	portal.MXID = ""
	err := portal.Save(ctx)
	if err != nil {
		return err
	}
	portal.Bridge.cacheLock.Lock()
	defer portal.Bridge.cacheLock.Unlock()
	delete(portal.Bridge.portalsByMXID, portal.MXID)
	return nil
}

func (portal *Portal) removeInPortalCache(ctx context.Context) {
	if portal.Receiver != "" {
		login := portal.Bridge.GetCachedUserLoginByID(portal.Receiver)
		if login != nil {
			login.inPortalCache.Remove(portal.PortalKey)
		}
		return
	}
	userPortals, err := portal.Bridge.DB.UserPortal.GetAllInPortal(ctx, portal.PortalKey)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to get user logins in portal to remove user portal cache")
	} else {
		for _, up := range userPortals {
			login := portal.Bridge.GetCachedUserLoginByID(up.LoginID)
			if login != nil {
				login.inPortalCache.Remove(portal.PortalKey)
			}
		}
	}
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
	if portal.events != nil {
		// TODO there's a small risk of this racing with a queueEvent call
		close(portal.events)
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

func (portal *Portal) PerMessageProfileForSender(ctx context.Context, sender networkid.UserID) (profile event.BeeperPerMessageProfile, err error) {
	var ghost *Ghost
	ghost, err = portal.Bridge.GetGhostByID(ctx, sender)
	if err != nil {
		return
	}
	profile.ID = string(ghost.Intent.GetMXID())
	profile.Displayname = ghost.Name
	if ghost.AvatarMXC != "" {
		profile.AvatarURL = &ghost.AvatarMXC
	}
	return
}
