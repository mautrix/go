// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"regexp"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/sqlstatestore"
)

type Crypto interface {
	HandleMemberEvent(context.Context, *event.Event)
	Decrypt(context.Context, *event.Event) (*event.Event, error)
	Encrypt(context.Context, id.RoomID, event.Type, *event.Content) error
	WaitForSession(context.Context, id.RoomID, id.SenderKey, id.SessionID, time.Duration) bool
	RequestSession(context.Context, id.RoomID, id.SenderKey, id.SessionID, id.UserID, id.DeviceID)
	ResetSession(context.Context, id.RoomID)
	Init(ctx context.Context) error
	Start()
	Stop()
	Reset(ctx context.Context, startAfterReset bool)
	Client() *mautrix.Client
	ShareKeys(context.Context) error
}

type Connector struct {
	//DB         *dbutil.Database
	AS         *appservice.AppService
	Bot        *appservice.IntentAPI
	StateStore *sqlstatestore.SQLStateStore
	Crypto     Crypto
	Log        *zerolog.Logger
	Config     *bridgeconfig.Config
	Bridge     *bridgev2.Bridge

	EventProcessor *appservice.EventProcessor

	userIDRegex *regexp.Regexp

	// TODO move to config
	AsyncUploads bool

	Websocket                      bool
	wsStopPinger                   chan struct{}
	wsStarted                      chan struct{}
	wsStopped                      chan struct{}
	wsShortCircuitReconnectBackoff chan struct{}
	wsStartupWait                  *sync.WaitGroup
}

func NewConnector(cfg *bridgeconfig.Config) *Connector {
	c := &Connector{}
	c.Config = cfg
	c.userIDRegex = cfg.MakeUserIDRegex("(.+)")
	return c
}

func (br *Connector) Init(bridge *bridgev2.Bridge) {
	br.Bridge = bridge
	br.Log = &bridge.Log
	br.StateStore = sqlstatestore.NewSQLStateStore(bridge.DB.Database, dbutil.ZeroLogger(br.Log.With().Str("db_section", "matrix").Logger()), false)
	br.AS = br.Config.MakeAppService()
	br.AS.Log = bridge.Log
	br.AS.StateStore = br.StateStore
	br.EventProcessor = appservice.NewEventProcessor(br.AS)
	for evtType := range status.CheckpointTypes {
		br.EventProcessor.On(evtType, br.sendBridgeCheckpoint)
	}
	br.EventProcessor.On(event.EventMessage, br.handleRoomEvent)
	br.EventProcessor.On(event.EventSticker, br.handleRoomEvent)
	br.EventProcessor.On(event.EventReaction, br.handleRoomEvent)
	br.EventProcessor.On(event.EventRedaction, br.handleRoomEvent)
	br.EventProcessor.On(event.EventEncrypted, br.handleEncryptedEvent)
	br.EventProcessor.On(event.StateMember, br.handleRoomEvent)
	br.Bot = br.AS.BotIntent()
	br.Crypto = NewCryptoHelper(br)
	br.Bridge.Commands.AddHandlers(CommandDiscardMegolmSession, CommandSetPowerLevel)
}

func (br *Connector) Start(ctx context.Context) error {
	br.EventProcessor.Start(ctx)
	err := br.StateStore.Upgrade(ctx)
	if err != nil {
		return err
	}
	go br.AS.Start()
	if br.Crypto != nil {
		err = br.Crypto.Init(ctx)
		if err != nil {
			return err
		}
		br.Crypto.Start()
	}
	return nil
}

var _ bridgev2.MatrixConnector = (*Connector)(nil)

func (br *Connector) GhostIntent(userID id.UserID) bridgev2.MatrixAPI {
	return &ASIntent{
		Matrix:    br.AS.Intent(userID),
		Connector: br,
	}
}

func (br *Connector) SendMessageStatus(ctx context.Context, evt bridgev2.MessageStatus) {
	log := zerolog.Ctx(ctx)
	err := br.SendMessageCheckpoints([]*status.MessageCheckpoint{evt.ToCheckpoint()})
	if err != nil {
		log.Err(err).Msg("Failed to send message checkpoint")
	}
}

func (br *Connector) SendMessageCheckpoints(checkpoints []*status.MessageCheckpoint) error {
	checkpointsJSON := status.CheckpointsJSON{Checkpoints: checkpoints}

	if br.Websocket {
		return br.AS.SendWebsocket(&appservice.WebsocketRequest{
			Command: "message_checkpoint",
			Data:    checkpointsJSON,
		})
	}

	endpoint := br.Config.Homeserver.MessageSendCheckpointEndpoint
	if endpoint == "" {
		return nil
	}

	return checkpointsJSON.SendHTTP(endpoint, br.AS.Registration.AppToken)
}

func (br *Connector) ParseGhostMXID(userID id.UserID) (networkid.UserID, bool) {
	match := br.userIDRegex.FindStringSubmatch(string(userID))
	if match == nil || userID == br.Bot.UserID {
		return "", false
	}
	decoded, err := id.DecodeUserLocalpart(match[1])
	if err != nil {
		return "", false
	}
	return networkid.UserID(decoded), true
}

func (br *Connector) FormatGhostMXID(userID networkid.UserID) id.UserID {
	localpart := br.Config.AppService.FormatUsername(id.EncodeUserLocalpart(string(userID)))
	return id.NewUserID(localpart, br.Config.Homeserver.Domain)
}

func (br *Connector) UserIntent(user *bridgev2.User) bridgev2.MatrixAPI {
	// TODO implement double puppeting
	return nil
}

func (br *Connector) BotIntent() bridgev2.MatrixAPI {
	return &ASIntent{Connector: br, Matrix: br.Bot}
}

func (br *Connector) GetMemberInfo(ctx context.Context, roomID id.RoomID, userID id.UserID) (*event.MemberEventContent, error) {
	// TODO fetch from network sometimes?
	return br.AS.StateStore.GetMember(ctx, roomID, userID)
}

func (br *Connector) ServerName() string {
	return br.Config.Homeserver.Domain
}
