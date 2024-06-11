// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
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
	AS           *appservice.AppService
	Bot          *appservice.IntentAPI
	StateStore   *sqlstatestore.SQLStateStore
	Crypto       Crypto
	Log          *zerolog.Logger
	Config       *bridgeconfig.Config
	Bridge       *bridgev2.Bridge
	Provisioning *ProvisioningAPI
	DoublePuppet *doublePuppetUtil

	MediaConfig             mautrix.RespMediaConfig
	SpecVersions            *mautrix.RespVersions
	IgnoreUnsupportedServer bool

	EventProcessor *appservice.EventProcessor

	userIDRegex *regexp.Regexp

	Websocket                      bool
	wsStopPinger                   chan struct{}
	wsStarted                      chan struct{}
	wsStopped                      chan struct{}
	wsShortCircuitReconnectBackoff chan struct{}
	wsStartupWait                  *sync.WaitGroup
}

var _ bridgev2.MatrixConnector = (*Connector)(nil)

func NewConnector(cfg *bridgeconfig.Config) *Connector {
	c := &Connector{}
	c.Config = cfg
	c.userIDRegex = cfg.MakeUserIDRegex("(.+)")
	c.MediaConfig.UploadSize = 50 * 1024 * 1024
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
	if !br.Config.AppService.AsyncTransactions {
		br.EventProcessor.ExecMode = appservice.Sync
	}
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
	br.Bridge.Commands.AddHandlers(
		CommandDiscardMegolmSession, CommandSetPowerLevel,
		CommandLoginMatrix, CommandPingMatrix, CommandLogoutMatrix,
	)
	br.Provisioning = &ProvisioningAPI{br: br}
	br.DoublePuppet = newDoublePuppetUtil(br)
}

func (br *Connector) Start(ctx context.Context) error {
	br.Provisioning.Init()
	err := br.StateStore.Upgrade(ctx)
	if err != nil {
		return bridgev2.DBUpgradeError{Section: "matrix_state", Err: err}
	}
	go br.AS.Start()
	br.ensureConnection(ctx)
	go br.fetchMediaConfig(ctx)
	if br.Crypto != nil {
		err = br.Crypto.Init(ctx)
		if err != nil {
			return err
		}
	}
	br.EventProcessor.Start(ctx)
	go br.UpdateBotProfile(ctx)
	if br.Crypto != nil {
		go br.Crypto.Start()
	}
	br.AS.Ready = true
	return nil
}

var MinSpecVersion = mautrix.SpecV14

func (br *Connector) ensureConnection(ctx context.Context) {
	for {
		versions, err := br.Bot.Versions(ctx)
		if err != nil {
			br.Log.Err(err).Msg("Failed to connect to homeserver, retrying in 10 seconds...")
			time.Sleep(10 * time.Second)
		} else {
			br.SpecVersions = versions
			break
		}
	}

	unsupportedServerLogLevel := zerolog.FatalLevel
	if br.IgnoreUnsupportedServer {
		unsupportedServerLogLevel = zerolog.ErrorLevel
	}
	if br.Config.Homeserver.Software == bridgeconfig.SoftwareHungry && !br.SpecVersions.Supports(mautrix.BeeperFeatureHungry) {
		br.Log.WithLevel(zerolog.FatalLevel).Msg("The config claims the homeserver is hungryserv, but the /versions response didn't confirm it")
		os.Exit(18)
	} else if !br.SpecVersions.ContainsGreaterOrEqual(MinSpecVersion) {
		br.Log.WithLevel(unsupportedServerLogLevel).
			Stringer("server_supports", br.SpecVersions.GetLatest()).
			Stringer("bridge_requires", MinSpecVersion).
			Msg("The homeserver is outdated (supported spec versions are below minimum required by bridge)")
		if !br.IgnoreUnsupportedServer {
			os.Exit(18)
		}
	}

	resp, err := br.Bot.Whoami(ctx)
	if err != nil {
		if errors.Is(err, mautrix.MUnknownToken) {
			br.Log.WithLevel(zerolog.FatalLevel).Msg("The as_token was not accepted. Is the registration file installed in your homeserver correctly?")
			br.Log.Info().Msg("See https://docs.mau.fi/faq/as-token for more info")
		} else if errors.Is(err, mautrix.MExclusive) {
			br.Log.WithLevel(zerolog.FatalLevel).Msg("The as_token was accepted, but the /register request was not. Are the homeserver domain, bot username and username template in the config correct, and do they match the values in the registration?")
			br.Log.Info().Msg("See https://docs.mau.fi/faq/as-register for more info")
		} else {
			br.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("/whoami request failed with unknown error")
		}
		os.Exit(16)
	} else if resp.UserID != br.Bot.UserID {
		br.Log.WithLevel(zerolog.FatalLevel).
			Stringer("got_user_id", resp.UserID).
			Stringer("expected_user_id", br.Bot.UserID).
			Msg("Unexpected user ID in whoami call")
		os.Exit(17)
	}

	if br.Websocket {
		br.Log.Debug().Msg("Websocket mode: no need to check status of homeserver -> bridge connection")
		return
	} else if !br.SpecVersions.Supports(mautrix.FeatureAppservicePing) {
		br.Log.Debug().Msg("Homeserver does not support checking status of homeserver -> bridge connection")
		return
	}
	var pingResp *mautrix.RespAppservicePing
	var txnID string
	var retryCount int
	const maxRetries = 6
	for {
		txnID = br.Bot.TxnID()
		pingResp, err = br.Bot.AppservicePing(ctx, br.Config.AppService.ID, txnID)
		if err == nil {
			break
		}
		var httpErr mautrix.HTTPError
		var pingErrBody string
		if errors.As(err, &httpErr) && httpErr.RespError != nil {
			if val, ok := httpErr.RespError.ExtraData["body"].(string); ok {
				pingErrBody = strings.TrimSpace(val)
			}
		}
		outOfRetries := retryCount >= maxRetries
		level := zerolog.ErrorLevel
		if outOfRetries {
			level = zerolog.FatalLevel
		}
		evt := br.Log.WithLevel(level).Err(err).Str("txn_id", txnID)
		if pingErrBody != "" {
			bodyBytes := []byte(pingErrBody)
			if json.Valid(bodyBytes) {
				evt.RawJSON("body", bodyBytes)
			} else {
				evt.Str("body", pingErrBody)
			}
		}
		if outOfRetries {
			evt.Msg("Homeserver -> bridge connection is not working")
			br.Log.Info().Msg("See https://docs.mau.fi/faq/as-ping for more info")
			os.Exit(13)
		}
		evt.Msg("Homeserver -> bridge connection is not working, retrying in 5 seconds...")
		time.Sleep(5 * time.Second)
		retryCount++
	}
	br.Log.Debug().
		Str("txn_id", txnID).
		Int64("duration_ms", pingResp.DurationMS).
		Msg("Homeserver -> bridge connection works")
}

func (br *Connector) fetchMediaConfig(ctx context.Context) {
	cfg, err := br.Bot.GetMediaConfig(ctx)
	if err != nil {
		br.Log.Warn().Err(err).Msg("Failed to fetch media config")
	} else {
		if cfg.UploadSize == 0 {
			cfg.UploadSize = 50 * 1024 * 1024
		}
		br.MediaConfig = *cfg
	}
}

func (br *Connector) UpdateBotProfile(ctx context.Context) {
	br.Log.Debug().Msg("Updating bot profile")
	botConfig := &br.Config.AppService.Bot

	var err error
	var mxc id.ContentURI
	if botConfig.Avatar == "remove" {
		err = br.Bot.SetAvatarURL(ctx, mxc)
	} else if !botConfig.ParsedAvatar.IsEmpty() {
		err = br.Bot.SetAvatarURL(ctx, botConfig.ParsedAvatar)
	}
	if err != nil {
		br.Log.Warn().Err(err).Msg("Failed to update bot avatar")
	}

	if botConfig.Displayname == "remove" {
		err = br.Bot.SetDisplayName(ctx, "")
	} else if len(botConfig.Displayname) > 0 {
		err = br.Bot.SetDisplayName(ctx, botConfig.Displayname)
	}
	if err != nil {
		br.Log.Warn().Err(err).Msg("Failed to update bot displayname")
	}

	if br.SpecVersions.Supports(mautrix.BeeperFeatureArbitraryProfileMeta) {
		br.Log.Debug().Msg("Setting contact info on the appservice bot")
		netName := br.Bridge.Network.GetName()
		err = br.Bot.BeeperUpdateProfile(ctx, event.BeeperProfileExtra{
			Service:     netName.BeeperBridgeType,
			Network:     netName.NetworkID,
			IsBridgeBot: true,
		})
		if err != nil {
			br.Log.Warn().Err(err).Msg("Failed to update bot contact info")
		}
	}
}

func (br *Connector) GhostIntent(userID id.UserID) bridgev2.MatrixAPI {
	return &ASIntent{
		Matrix:    br.AS.Intent(userID),
		Connector: br,
	}
}

func (br *Connector) SendMessageStatus(ctx context.Context, ms *bridgev2.MessageStatus, evt *bridgev2.MessageStatusEventInfo) {
	br.internalSendMessageStatus(ctx, ms, evt, "")
}

func (br *Connector) internalSendMessageStatus(ctx context.Context, ms *bridgev2.MessageStatus, evt *bridgev2.MessageStatusEventInfo, editEvent id.EventID) id.EventID {
	log := zerolog.Ctx(ctx)
	err := br.SendMessageCheckpoints([]*status.MessageCheckpoint{ms.ToCheckpoint(evt)})
	if err != nil {
		log.Err(err).Msg("Failed to send message checkpoint")
	}
	if !ms.DisableMSS && br.Config.Matrix.MessageStatusEvents {
		_, err = br.Bot.SendMessageEvent(ctx, evt.RoomID, event.BeeperMessageStatus, ms.ToMSSEvent(evt))
		if err != nil {
			log.Err(err).Msg("Failed to send MSS event")
		}
	}
	if ms.SendNotice && br.Config.Matrix.MessageErrorNotices && (ms.Status == event.MessageStatusFail || ms.Status == event.MessageStatusRetriable || ms.Step == status.MsgStepDecrypted) {
		content := ms.ToNoticeEvent(evt)
		if editEvent != "" {
			content.SetEdit(editEvent)
		}
		resp, err := br.Bot.SendMessageEvent(ctx, evt.RoomID, event.EventMessage, content)
		if err != nil {
			log.Err(err).Msg("Failed to send notice event")
		} else {
			return resp.EventID
		}
	}
	if ms.Status == event.MessageStatusSuccess && br.Config.Matrix.DeliveryReceipts {
		err = br.Bot.SendReceipt(ctx, evt.RoomID, evt.EventID, event.ReceiptTypeRead, nil)
		if err != nil {
			log.Err(err).Msg("Failed to send Matrix delivery receipt")
		}
	}
	return ""
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

func (br *Connector) NewUserIntent(ctx context.Context, userID id.UserID, accessToken string) (bridgev2.MatrixAPI, string, error) {
	intent, newToken, err := br.DoublePuppet.Setup(ctx, userID, accessToken)
	if err != nil {
		if errors.Is(err, ErrNoAccessToken) {
			err = nil
		}
		return nil, accessToken, err
	}
	return &ASIntent{Connector: br, Matrix: intent}, newToken, nil
}

func (br *Connector) BotIntent() bridgev2.MatrixAPI {
	return &ASIntent{Connector: br, Matrix: br.Bot}
}

func (br *Connector) GetMembers(ctx context.Context, roomID id.RoomID) (map[id.UserID]*event.MemberEventContent, error) {
	// TODO use cache?
	members, err := br.Bot.Members(ctx, roomID)
	if err != nil {
		return nil, err
	}
	output := make(map[id.UserID]*event.MemberEventContent, len(members.Chunk))
	for _, evt := range members.Chunk {
		_ = evt.Content.ParseRaw(evt.Type)
		output[id.UserID(evt.GetStateKey())] = evt.Content.AsMember()
	}
	return output, nil
}

func (br *Connector) GetMemberInfo(ctx context.Context, roomID id.RoomID, userID id.UserID) (*event.MemberEventContent, error) {
	// TODO fetch from network sometimes?
	return br.AS.StateStore.GetMember(ctx, roomID, userID)
}

func (br *Connector) ServerName() string {
	return br.Config.Homeserver.Domain
}
