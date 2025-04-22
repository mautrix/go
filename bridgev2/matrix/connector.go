// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	_ "go.mau.fi/util/dbutil/litestream"
	"go.mau.fi/util/exsync"
	"go.mau.fi/util/random"
	"golang.org/x/sync/semaphore"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/commands"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mediaproxy"
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
	AS           *appservice.AppService
	Bot          *appservice.IntentAPI
	StateStore   *sqlstatestore.SQLStateStore
	Crypto       Crypto
	Log          *zerolog.Logger
	Config       *bridgeconfig.Config
	Bridge       *bridgev2.Bridge
	Provisioning *ProvisioningAPI
	DoublePuppet *doublePuppetUtil
	MediaProxy   *mediaproxy.MediaProxy

	uploadSema     *semaphore.Weighted
	dmaSigKey      [32]byte
	pubMediaSigKey []byte

	doublePuppetIntents *exsync.Map[id.UserID, *appservice.IntentAPI]

	deterministicEventIDServer string

	MediaConfig             mautrix.RespMediaConfig
	SpecVersions            *mautrix.RespVersions
	Capabilities            *bridgev2.MatrixCapabilities
	IgnoreUnsupportedServer bool

	EventProcessor *appservice.EventProcessor

	userIDRegex *regexp.Regexp

	Websocket                      bool
	wsStopPinger                   chan struct{}
	wsStarted                      chan struct{}
	wsStopped                      chan struct{}
	wsShortCircuitReconnectBackoff chan struct{}
	wsStartupWait                  *sync.WaitGroup
	stopping                       bool
	hasSentAnyStates               bool
	OnWebsocketReplaced            func()
}

var (
	_ bridgev2.MatrixConnector                           = (*Connector)(nil)
	_ bridgev2.MatrixConnectorWithServer                 = (*Connector)(nil)
	_ bridgev2.MatrixConnectorWithPostRoomBridgeHandling = (*Connector)(nil)
	_ bridgev2.MatrixConnectorWithPublicMedia            = (*Connector)(nil)
	_ bridgev2.MatrixConnectorWithNameDisambiguation     = (*Connector)(nil)
	_ bridgev2.MatrixConnectorWithURLPreviews            = (*Connector)(nil)
	_ bridgev2.MatrixConnectorWithAnalytics              = (*Connector)(nil)
)

func NewConnector(cfg *bridgeconfig.Config) *Connector {
	c := &Connector{}
	c.Config = cfg
	c.userIDRegex = cfg.MakeUserIDRegex("(.+)")
	c.MediaConfig.UploadSize = 50 * 1024 * 1024
	c.uploadSema = semaphore.NewWeighted(c.MediaConfig.UploadSize + 1)
	c.Capabilities = &bridgev2.MatrixCapabilities{}
	c.doublePuppetIntents = exsync.NewMap[id.UserID, *appservice.IntentAPI]()
	return c
}

func (br *Connector) Init(bridge *bridgev2.Bridge) {
	br.Bridge = bridge
	br.Log = &bridge.Log
	br.StateStore = sqlstatestore.NewSQLStateStore(bridge.DB.Database, dbutil.ZeroLogger(br.Log.With().Str("db_section", "matrix_state").Logger()), false)
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
	br.EventProcessor.On(event.EventUnstablePollStart, br.handleRoomEvent)
	br.EventProcessor.On(event.EventUnstablePollResponse, br.handleRoomEvent)
	br.EventProcessor.On(event.EventReaction, br.handleRoomEvent)
	br.EventProcessor.On(event.EventRedaction, br.handleRoomEvent)
	br.EventProcessor.On(event.EventEncrypted, br.handleEncryptedEvent)
	br.EventProcessor.On(event.StateMember, br.handleRoomEvent)
	br.EventProcessor.On(event.StatePowerLevels, br.handleRoomEvent)
	br.EventProcessor.On(event.StateRoomName, br.handleRoomEvent)
	br.EventProcessor.On(event.StateRoomAvatar, br.handleRoomEvent)
	br.EventProcessor.On(event.StateTopic, br.handleRoomEvent)
	br.EventProcessor.On(event.EphemeralEventReceipt, br.handleEphemeralEvent)
	br.EventProcessor.On(event.EphemeralEventTyping, br.handleEphemeralEvent)
	br.Bot = br.AS.BotIntent()
	br.Crypto = NewCryptoHelper(br)
	br.Bridge.Commands.(*commands.Processor).AddHandlers(
		CommandDiscardMegolmSession, CommandSetPowerLevel,
		CommandLoginMatrix, CommandPingMatrix, CommandLogoutMatrix,
	)
	br.Provisioning = &ProvisioningAPI{br: br}
	br.DoublePuppet = newDoublePuppetUtil(br)
	br.deterministicEventIDServer = "backfill." + br.Config.Homeserver.Domain
}

func (br *Connector) Start(ctx context.Context) error {
	br.Provisioning.Init()
	err := br.initDirectMedia()
	if err != nil {
		return err
	}
	err = br.initPublicMedia()
	if err != nil {
		return err
	}
	err = br.StateStore.Upgrade(ctx)
	if err != nil {
		return bridgev2.DBUpgradeError{Section: "matrix_state", Err: err}
	}
	if br.Config.Homeserver.Websocket || len(br.Config.Homeserver.WSProxy) > 0 {
		br.Websocket = true
		br.Log.Debug().Msg("Starting appservice websocket")
		var wg sync.WaitGroup
		wg.Add(1)
		br.wsStartupWait = &wg
		br.wsShortCircuitReconnectBackoff = make(chan struct{})
		go br.startWebsocket(&wg)
	} else if br.AS.Host.IsConfigured() {
		br.Log.Debug().Msg("Starting appservice HTTP server")
		go br.AS.Start()
	} else {
		br.Log.WithLevel(zerolog.FatalLevel).Msg("Neither appservice HTTP listener nor websocket is enabled")
		os.Exit(23)
	}

	br.Log.Debug().Msg("Checking connection to homeserver")
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
	parsed, _ := url.Parse(br.Bridge.Network.GetName().NetworkURL)
	if parsed != nil {
		br.deterministicEventIDServer = strings.TrimPrefix(parsed.Hostname(), "www.")
	}
	br.AS.Ready = true
	if br.Websocket && br.Config.Homeserver.WSPingInterval > 0 {
		br.wsStopPinger = make(chan struct{}, 1)
		go br.websocketServerPinger()
	}
	return nil
}

func (br *Connector) GetPublicAddress() string {
	if br.Config.AppService.PublicAddress == "https://bridge.example.com" {
		return ""
	}
	return br.Config.AppService.PublicAddress
}

func (br *Connector) GetRouter() *mux.Router {
	if br.GetPublicAddress() != "" {
		return br.AS.Router
	}
	return nil
}

func (br *Connector) GetCapabilities() *bridgev2.MatrixCapabilities {
	return br.Capabilities
}

func sendStopSignal(ch chan struct{}) {
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (br *Connector) PreStop() {
	br.stopping = true
	br.AS.Stop()
	if stopWebsocket := br.AS.StopWebsocket; stopWebsocket != nil {
		stopWebsocket(appservice.ErrWebsocketManualStop)
	}
	sendStopSignal(br.wsStopPinger)
	sendStopSignal(br.wsShortCircuitReconnectBackoff)
}

func (br *Connector) Stop() {
	br.EventProcessor.Stop()
	if br.Crypto != nil {
		br.Crypto.Stop()
	}
	if wsStopChan := br.wsStopped; wsStopChan != nil {
		select {
		case <-wsStopChan:
		case <-time.After(4 * time.Second):
			br.Log.Warn().Msg("Timed out waiting for websocket to close")
		}
	}
}

var MinSpecVersion = mautrix.SpecV14

func (br *Connector) logInitialRequestError(err error, defaultMessage string) {
	if errors.Is(err, mautrix.MUnknownToken) {
		br.Log.WithLevel(zerolog.FatalLevel).Msg("The as_token was not accepted. Is the registration file installed in your homeserver correctly?")
		br.Log.Info().Msg("See https://docs.mau.fi/faq/as-token for more info")
	} else if errors.Is(err, mautrix.MExclusive) {
		br.Log.WithLevel(zerolog.FatalLevel).Msg("The as_token was accepted, but the /register request was not. Are the homeserver domain, bot username and username template in the config correct, and do they match the values in the registration?")
		br.Log.Info().Msg("See https://docs.mau.fi/faq/as-register for more info")
	} else {
		br.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg(defaultMessage)
	}
}

func (br *Connector) ensureConnection(ctx context.Context) {
	for {
		versions, err := br.Bot.Versions(ctx)
		if err != nil {
			if errors.Is(err, mautrix.MForbidden) {
				br.Log.Debug().Msg("M_FORBIDDEN in /versions, trying to register before retrying")
				err = br.Bot.EnsureRegistered(ctx)
				if err != nil {
					br.logInitialRequestError(err, "Failed to register after /versions failed with M_FORBIDDEN")
					os.Exit(16)
				}
			} else if errors.Is(err, mautrix.MUnknownToken) || errors.Is(err, mautrix.MExclusive) {
				br.logInitialRequestError(err, "/versions request failed with auth error")
				os.Exit(16)
			} else {
				br.Log.Err(err).Msg("Failed to connect to homeserver, retrying in 10 seconds...")
				time.Sleep(10 * time.Second)
			}
		} else {
			br.SpecVersions = versions
			*br.AS.SpecVersions = *versions
			br.Capabilities.AutoJoinInvites = br.SpecVersions.Supports(mautrix.BeeperFeatureAutojoinInvites)
			br.Capabilities.BatchSending = br.SpecVersions.Supports(mautrix.BeeperFeatureBatchSending)
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
		br.logInitialRequestError(err, "/whoami request failed with unknown error")
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
		mfsn, ok := br.Bridge.Network.(bridgev2.MaxFileSizeingNetwork)
		if ok {
			mfsn.SetMaxFileSize(br.MediaConfig.UploadSize)
		}
		br.uploadSema = semaphore.NewWeighted(br.MediaConfig.UploadSize + 1)
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

func (br *Connector) GhostIntent(userID networkid.UserID) bridgev2.MatrixAPI {
	return &ASIntent{
		Matrix:    br.AS.Intent(br.FormatGhostMXID(userID)),
		Connector: br,
	}
}

func (br *Connector) SendBridgeStatus(ctx context.Context, state *status.BridgeState) error {
	if br.Websocket {
		br.hasSentAnyStates = true
		return br.AS.SendWebsocket(&appservice.WebsocketRequest{
			Command: "bridge_status",
			Data:    state,
		})
	} else if br.Config.Homeserver.StatusEndpoint != "" {
		return state.SendHTTP(ctx, br.Config.Homeserver.StatusEndpoint, br.Config.AppService.ASToken)
	} else {
		return nil
	}
}

func (br *Connector) SendMessageStatus(ctx context.Context, ms *bridgev2.MessageStatus, evt *bridgev2.MessageStatusEventInfo) {
	go br.internalSendMessageStatus(ctx, ms, evt, "")
}

func (br *Connector) internalSendMessageStatus(ctx context.Context, ms *bridgev2.MessageStatus, evt *bridgev2.MessageStatusEventInfo, editEvent id.EventID) id.EventID {
	if evt.EventType.IsEphemeral() || evt.SourceEventID == "" {
		return ""
	}
	log := zerolog.Ctx(ctx)

	if !evt.IsSourceEventDoublePuppeted {
		err := br.SendMessageCheckpoints([]*status.MessageCheckpoint{ms.ToCheckpoint(evt)})
		if err != nil {
			log.Err(err).Msg("Failed to send message checkpoint")
		}
	}

	if !ms.DisableMSS && br.Config.Matrix.MessageStatusEvents {
		mssEvt := ms.ToMSSEvent(evt)
		_, err := br.Bot.SendMessageEvent(ctx, evt.RoomID, event.BeeperMessageStatus, mssEvt)
		if err != nil {
			log.Err(err).
				Stringer("room_id", evt.RoomID).
				Stringer("event_id", evt.SourceEventID).
				Any("mss_content", mssEvt).
				Msg("Failed to send MSS event")
		}
	}
	if ms.SendNotice && br.Config.Matrix.MessageErrorNotices && (ms.Status == event.MessageStatusFail || ms.Status == event.MessageStatusRetriable || ms.Step == status.MsgStepDecrypted) {
		content := ms.ToNoticeEvent(evt)
		if editEvent != "" {
			content.SetEdit(editEvent)
		}
		resp, err := br.Bot.SendMessageEvent(ctx, evt.RoomID, event.EventMessage, content)
		if err != nil {
			log.Err(err).
				Stringer("room_id", evt.RoomID).
				Stringer("event_id", evt.SourceEventID).
				Str("notice_message", content.Body).
				Msg("Failed to send notice event")
		} else {
			return resp.EventID
		}
	}
	if ms.Status == event.MessageStatusSuccess && br.Config.Matrix.DeliveryReceipts {
		err := br.Bot.SendReceipt(ctx, evt.RoomID, evt.SourceEventID, event.ReceiptTypeRead, nil)
		if err != nil {
			log.Err(err).
				Stringer("room_id", evt.RoomID).
				Stringer("event_id", evt.SourceEventID).
				Msg("Failed to send Matrix delivery receipt")
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
	br.doublePuppetIntents.Set(userID, intent)
	return &ASIntent{Connector: br, Matrix: intent}, newToken, nil
}

func (br *Connector) BotIntent() bridgev2.MatrixAPI {
	return &ASIntent{Connector: br, Matrix: br.Bot}
}

func (br *Connector) GetPowerLevels(ctx context.Context, roomID id.RoomID) (*event.PowerLevelsEventContent, error) {
	return br.Bot.PowerLevels(ctx, roomID)
}

func (br *Connector) GetMembers(ctx context.Context, roomID id.RoomID) (map[id.UserID]*event.MemberEventContent, error) {
	fetched, err := br.Bot.StateStore.HasFetchedMembers(ctx, roomID)
	if err != nil {
		return nil, err
	} else if fetched {
		return br.Bot.StateStore.GetAllMembers(ctx, roomID)
	}
	members, err := br.Bot.Members(ctx, roomID)
	if err != nil {
		return nil, err
	}
	output := make(map[id.UserID]*event.MemberEventContent, len(members.Chunk))
	for _, evt := range members.Chunk {
		output[id.UserID(evt.GetStateKey())] = evt.Content.AsMember()
	}
	return output, nil
}

func (br *Connector) GetMemberInfo(ctx context.Context, roomID id.RoomID, userID id.UserID) (*event.MemberEventContent, error) {
	// TODO fetch from network sometimes?
	return br.AS.StateStore.GetMember(ctx, roomID, userID)
}

func (br *Connector) IsConfusableName(ctx context.Context, roomID id.RoomID, userID id.UserID, name string) ([]id.UserID, error) {
	return br.AS.StateStore.IsConfusableName(ctx, roomID, userID, name)
}

func (br *Connector) GetUniqueBridgeID() string {
	return fmt.Sprintf("%s/%s", br.Config.Homeserver.Domain, br.Config.AppService.ID)
}

func (br *Connector) BatchSend(ctx context.Context, roomID id.RoomID, req *mautrix.ReqBeeperBatchSend, extras []*bridgev2.MatrixSendExtra) (*mautrix.RespBeeperBatchSend, error) {
	if encrypted, err := br.StateStore.IsEncrypted(ctx, roomID); err != nil {
		return nil, fmt.Errorf("failed to check if room is encrypted: %w", err)
	} else if encrypted {
		for _, evt := range req.Events {
			intent, _ := br.doublePuppetIntents.Get(evt.Sender)
			if intent != nil {
				intent.AddDoublePuppetValueWithTS(&evt.Content, evt.Timestamp)
			}
			if evt.Type != event.EventEncrypted {
				err = br.Crypto.Encrypt(ctx, roomID, evt.Type, &evt.Content)
				if err != nil {
					return nil, err
				}
				evt.Type = event.EventEncrypted
				if intent != nil {
					intent.AddDoublePuppetValueWithTS(&evt.Content, evt.Timestamp)
				}
			}
		}
	}
	return br.Bot.BeeperBatchSend(ctx, roomID, req)
}

func (br *Connector) GenerateDeterministicEventID(roomID id.RoomID, _ networkid.PortalKey, messageID networkid.MessageID, partID networkid.PartID) id.EventID {
	data := make([]byte, 0, len(roomID)+1+len(messageID)+1+len(partID))
	data = append(data, roomID...)
	data = append(data, 0)
	data = append(data, messageID...)
	data = append(data, 0)
	data = append(data, partID...)

	hash := sha256.Sum256(data)
	hashB64Len := base64.RawURLEncoding.EncodedLen(len(hash))

	eventID := make([]byte, 1+hashB64Len+1+len(br.deterministicEventIDServer))
	eventID[0] = '$'
	base64.RawURLEncoding.Encode(eventID[1:1+hashB64Len], hash[:])
	eventID[1+hashB64Len] = ':'
	copy(eventID[1+hashB64Len+1:], br.deterministicEventIDServer)

	return id.EventID(unsafe.String(unsafe.SliceData(eventID), len(eventID)))
}

func (br *Connector) GenerateDeterministicRoomID(key networkid.PortalKey) id.RoomID {
	return id.RoomID(fmt.Sprintf("!%s.%s:%s", key.ID, key.Receiver, br.ServerName()))
}

func (br *Connector) GenerateReactionEventID(roomID id.RoomID, targetMessage *database.Message, sender networkid.UserID, emojiID networkid.EmojiID) id.EventID {
	// We don't care about determinism for reactions
	return id.EventID(fmt.Sprintf("$%s:%s", base64.RawURLEncoding.EncodeToString(random.Bytes(32)), br.deterministicEventIDServer))
}

func (br *Connector) ServerName() string {
	return br.Config.Homeserver.Domain
}

func (br *Connector) HandleNewlyBridgedRoom(ctx context.Context, roomID id.RoomID) error {
	_, err := br.Bot.Members(ctx, roomID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to fetch members in newly bridged room")
	}
	if !br.Config.Encryption.Default {
		return nil
	}
	_, err = br.Bot.SendStateEvent(ctx, roomID, event.StateEncryption, "", &event.Content{
		Parsed: br.getDefaultEncryptionEvent(),
	})
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to enable encryption in newly bridged room")
		return fmt.Errorf("failed to enable encryption")
	}
	return nil
}

func (br *Connector) GetURLPreview(ctx context.Context, url string) (*event.LinkPreview, error) {
	return br.Bot.GetURLPreview(ctx, url)
}
