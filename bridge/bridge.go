// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lib/pq"
	"github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"go.mau.fi/util/configupgrade"
	"go.mau.fi/util/dbutil"
	_ "go.mau.fi/util/dbutil/litestream"
	"go.mau.fi/util/exzerolog"
	"gopkg.in/yaml.v3"
	flag "maunium.net/go/mauflag"
	"maunium.net/go/maulogger/v2"
	"maunium.net/go/maulogger/v2/maulogadapt"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/appservice"
	"github.com/element-hq/mautrix-go/bridge/bridgeconfig"
	"github.com/element-hq/mautrix-go/bridge/status"
	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
	"github.com/element-hq/mautrix-go/sqlstatestore"
)

var configPath = flag.MakeFull("c", "config", "The path to your config file.", "config.yaml").String()
var dontSaveConfig = flag.MakeFull("n", "no-update", "Don't save updated config to disk.", "false").Bool()
var registrationPath = flag.MakeFull("r", "registration", "The path where to save the appservice registration.", "registration.yaml").String()
var generateRegistration = flag.MakeFull("g", "generate-registration", "Generate registration and quit.", "false").Bool()
var version = flag.MakeFull("v", "version", "View bridge version and quit.", "false").Bool()
var versionJSON = flag.Make().LongKey("version-json").Usage("Print a JSON object representing the bridge version and quit.").Default("false").Bool()
var ignoreUnsupportedDatabase = flag.Make().LongKey("ignore-unsupported-database").Usage("Run even if the database schema is too new").Default("false").Bool()
var ignoreForeignTables = flag.Make().LongKey("ignore-foreign-tables").Usage("Run even if the database contains tables from other programs (like Synapse)").Default("false").Bool()
var ignoreUnsupportedServer = flag.Make().LongKey("ignore-unsupported-server").Usage("Run even if the Matrix homeserver is outdated").Default("false").Bool()
var wantHelp, _ = flag.MakeHelpFlag()

var _ appservice.StateStore = (*sqlstatestore.SQLStateStore)(nil)

type Portal interface {
	IsEncrypted() bool
	IsPrivateChat() bool
	MarkEncrypted()
	MainIntent() *appservice.IntentAPI

	ReceiveMatrixEvent(user User, evt *event.Event)
	UpdateBridgeInfo(ctx context.Context)
}

type MembershipHandlingPortal interface {
	Portal
	HandleMatrixLeave(sender User, evt *event.Event)
	HandleMatrixKick(sender User, ghost Ghost, evt *event.Event)
	HandleMatrixInvite(sender User, ghost Ghost, evt *event.Event)
}

type ReadReceiptHandlingPortal interface {
	Portal
	HandleMatrixReadReceipt(sender User, eventID id.EventID, receipt event.ReadReceipt)
}

type TypingPortal interface {
	Portal
	HandleMatrixTyping(userIDs []id.UserID)
}

type MetaHandlingPortal interface {
	Portal
	HandleMatrixMeta(sender User, evt *event.Event)
}

type DisappearingPortal interface {
	Portal
	ScheduleDisappearing()
}

type User interface {
	GetPermissionLevel() bridgeconfig.PermissionLevel
	IsLoggedIn() bool
	GetManagementRoomID() id.RoomID
	SetManagementRoom(id.RoomID)
	GetMXID() id.UserID
	GetIDoublePuppet() DoublePuppet
	GetIGhost() Ghost
}

type DoublePuppet interface {
	CustomIntent() *appservice.IntentAPI
	SwitchCustomMXID(accessToken string, userID id.UserID) error
	ClearCustomMXID()
}

type Ghost interface {
	DoublePuppet
	DefaultIntent() *appservice.IntentAPI
	GetMXID() id.UserID
}

type GhostWithProfile interface {
	Ghost
	GetDisplayname() string
	GetAvatarURL() id.ContentURI
}

type ChildOverride interface {
	GetExampleConfig() string
	GetConfigPtr() interface{}

	Init()
	Start()
	Stop()

	GetIPortal(id.RoomID) Portal
	GetAllIPortals() []Portal
	GetIUser(id id.UserID, create bool) User
	IsGhost(id.UserID) bool
	GetIGhost(id.UserID) Ghost
	CreatePrivatePortal(id.RoomID, User, Ghost)
}

type ConfigValidatingBridge interface {
	ChildOverride
	ValidateConfig() error
}

type FlagHandlingBridge interface {
	ChildOverride
	HandleFlags() bool
}

type PreInitableBridge interface {
	ChildOverride
	PreInit()
}

type WebsocketStartingBridge interface {
	ChildOverride
	OnWebsocketConnect()
}

type CSFeatureRequirer interface {
	CheckFeatures(versions *mautrix.RespVersions) (string, bool)
}

type Bridge struct {
	Name              string
	URL               string
	Description       string
	Version           string
	ProtocolName      string
	BeeperServiceName string
	BeeperNetworkName string

	AdditionalShortFlags string
	AdditionalLongFlags  string

	VersionDesc      string
	LinkifiedVersion string
	BuildTime        string
	commit           string
	baseVersion      string

	PublicHSAddress *url.URL

	DoublePuppet *doublePuppetUtil

	AS               *appservice.AppService
	EventProcessor   *appservice.EventProcessor
	CommandProcessor CommandProcessor
	MatrixHandler    *MatrixHandler
	Bot              *appservice.IntentAPI
	Config           bridgeconfig.BaseConfig
	ConfigPath       string
	RegistrationPath string
	SaveConfig       bool
	ConfigUpgrader   configupgrade.BaseUpgrader
	DB               *dbutil.Database
	StateStore       *sqlstatestore.SQLStateStore
	Crypto           Crypto
	CryptoPickleKey  string

	// Deprecated: Switch to ZLog
	Log  maulogger.Logger
	ZLog *zerolog.Logger

	MediaConfig  mautrix.RespMediaConfig
	SpecVersions mautrix.RespVersions

	Child ChildOverride

	manualStop chan int
	Stopping   bool

	latestState *status.BridgeState

	Websocket                      bool
	wsStopPinger                   chan struct{}
	wsStarted                      chan struct{}
	wsStopped                      chan struct{}
	wsShortCircuitReconnectBackoff chan struct{}
	wsStartupWait                  *sync.WaitGroup
}

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

func (br *Bridge) GenerateRegistration() {
	if !br.SaveConfig {
		// We need to save the generated as_token and hs_token in the config
		_, _ = fmt.Fprintln(os.Stderr, "--no-update is not compatible with --generate-registration")
		os.Exit(5)
	} else if br.Config.Homeserver.Domain == "example.com" {
		_, _ = fmt.Fprintln(os.Stderr, "Homeserver domain is not set")
		os.Exit(20)
	}
	reg := br.Config.GenerateRegistration()
	err := reg.Save(br.RegistrationPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to save registration:", err)
		os.Exit(21)
	}

	updateTokens := func(helper *configupgrade.Helper) {
		helper.Set(configupgrade.Str, reg.AppToken, "appservice", "as_token")
		helper.Set(configupgrade.Str, reg.ServerToken, "appservice", "hs_token")
	}
	_, _, err = configupgrade.Do(br.ConfigPath, true, br.ConfigUpgrader, configupgrade.SimpleUpgrader(updateTokens))
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to save config:", err)
		os.Exit(22)
	}
	fmt.Println("Registration generated. See https://docs.mau.fi/bridges/general/registering-appservices.html for instructions on installing the registration.")
	os.Exit(0)
}

func (br *Bridge) InitVersion(tag, commit, buildTime string) {
	br.baseVersion = br.Version
	if len(tag) > 0 && tag[0] == 'v' {
		tag = tag[1:]
	}
	if tag != br.Version {
		suffix := ""
		if !strings.HasSuffix(br.Version, "+dev") {
			suffix = "+dev"
		}
		if len(commit) > 8 {
			br.Version = fmt.Sprintf("%s%s.%s", br.Version, suffix, commit[:8])
		} else {
			br.Version = fmt.Sprintf("%s%s.unknown", br.Version, suffix)
		}
	}

	br.LinkifiedVersion = fmt.Sprintf("v%s", br.Version)
	if tag == br.Version {
		br.LinkifiedVersion = fmt.Sprintf("[v%s](%s/releases/v%s)", br.Version, br.URL, tag)
	} else if len(commit) > 8 {
		br.LinkifiedVersion = strings.Replace(br.LinkifiedVersion, commit[:8], fmt.Sprintf("[%s](%s/commit/%s)", commit[:8], br.URL, commit), 1)
	}
	mautrix.DefaultUserAgent = fmt.Sprintf("%s/%s %s", br.Name, br.Version, mautrix.DefaultUserAgent)
	br.VersionDesc = fmt.Sprintf("%s %s (%s with %s)", br.Name, br.Version, buildTime, runtime.Version())
	br.commit = commit
	br.BuildTime = buildTime
}

var MinSpecVersion = mautrix.SpecV14

func (br *Bridge) ensureConnection(ctx context.Context) {
	for {
		versions, err := br.Bot.Versions(ctx)
		if err != nil {
			br.ZLog.Err(err).Msg("Failed to connect to homeserver, retrying in 10 seconds...")
			time.Sleep(10 * time.Second)
		} else {
			br.SpecVersions = *versions
			break
		}
	}

	unsupportedServerLogLevel := zerolog.FatalLevel
	if *ignoreUnsupportedServer {
		unsupportedServerLogLevel = zerolog.ErrorLevel
	}
	if br.Config.Homeserver.Software == bridgeconfig.SoftwareHungry && !br.SpecVersions.Supports(mautrix.BeeperFeatureHungry) {
		br.ZLog.WithLevel(zerolog.FatalLevel).Msg("The config claims the homeserver is hungryserv, but the /versions response didn't confirm it")
		os.Exit(18)
	} else if !br.SpecVersions.ContainsGreaterOrEqual(MinSpecVersion) {
		br.ZLog.WithLevel(unsupportedServerLogLevel).
			Stringer("server_supports", br.SpecVersions.GetLatest()).
			Stringer("bridge_requires", MinSpecVersion).
			Msg("The homeserver is outdated (supported spec versions are below minimum required by bridge)")
		if !*ignoreUnsupportedServer {
			os.Exit(18)
		}
	} else if fr, ok := br.Child.(CSFeatureRequirer); ok {
		if msg, hasFeatures := fr.CheckFeatures(&br.SpecVersions); !hasFeatures {
			br.ZLog.WithLevel(unsupportedServerLogLevel).Msg(msg)
			if !*ignoreUnsupportedServer {
				os.Exit(18)
			}
		}
	}

	resp, err := br.Bot.Whoami(ctx)
	if err != nil {
		if errors.Is(err, mautrix.MUnknownToken) {
			br.ZLog.WithLevel(zerolog.FatalLevel).Msg("The as_token was not accepted. Is the registration file installed in your homeserver correctly?")
		} else if errors.Is(err, mautrix.MExclusive) {
			br.ZLog.WithLevel(zerolog.FatalLevel).Msg("The as_token was accepted, but the /register request was not. Are the homeserver domain, bot username and username template in the config correct, and do they match the values in the registration?")
		} else {
			br.ZLog.WithLevel(zerolog.FatalLevel).Err(err).Msg("/whoami request failed with unknown error")
		}
		os.Exit(16)
	} else if resp.UserID != br.Bot.UserID {
		br.ZLog.WithLevel(zerolog.FatalLevel).
			Stringer("got_user_id", resp.UserID).
			Stringer("expected_user_id", br.Bot.UserID).
			Msg("Unexpected user ID in whoami call")
		os.Exit(17)
	}

	if br.Websocket {
		br.ZLog.Debug().Msg("Websocket mode: no need to check status of homeserver -> bridge connection")
		return
	} else if !br.SpecVersions.Supports(mautrix.FeatureAppservicePing) {
		br.ZLog.Debug().Msg("Homeserver does not support checking status of homeserver -> bridge connection")
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
		evt := br.ZLog.WithLevel(level).Err(err).Str("txn_id", txnID)
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
			os.Exit(13)
		}
		evt.Msg("Homeserver -> bridge connection is not working, retrying in 5 seconds...")
		time.Sleep(5 * time.Second)
		retryCount++
	}
	br.ZLog.Debug().
		Str("txn_id", txnID).
		Int64("duration_ms", pingResp.DurationMS).
		Msg("Homeserver -> bridge connection works")
}

func (br *Bridge) fetchMediaConfig(ctx context.Context) {
	cfg, err := br.Bot.GetMediaConfig(ctx)
	if err != nil {
		br.ZLog.Warn().Err(err).Msg("Failed to fetch media config")
	} else {
		br.MediaConfig = *cfg
	}
}

func (br *Bridge) UpdateBotProfile(ctx context.Context) {
	br.ZLog.Debug().Msg("Updating bot profile")
	botConfig := &br.Config.AppService.Bot

	var err error
	var mxc id.ContentURI
	if botConfig.Avatar == "remove" {
		err = br.Bot.SetAvatarURL(ctx, mxc)
	} else if !botConfig.ParsedAvatar.IsEmpty() {
		err = br.Bot.SetAvatarURL(ctx, botConfig.ParsedAvatar)
	}
	if err != nil {
		br.ZLog.Warn().Err(err).Msg("Failed to update bot avatar")
	}

	if botConfig.Displayname == "remove" {
		err = br.Bot.SetDisplayName(ctx, "")
	} else if len(botConfig.Displayname) > 0 {
		err = br.Bot.SetDisplayName(ctx, botConfig.Displayname)
	}
	if err != nil {
		br.ZLog.Warn().Err(err).Msg("Failed to update bot displayname")
	}

	if br.SpecVersions.Supports(mautrix.BeeperFeatureArbitraryProfileMeta) && br.BeeperNetworkName != "" {
		br.ZLog.Debug().Msg("Setting contact info on the appservice bot")
		br.Bot.BeeperUpdateProfile(ctx, map[string]any{
			"com.beeper.bridge.service":       br.BeeperServiceName,
			"com.beeper.bridge.network":       br.BeeperNetworkName,
			"com.beeper.bridge.is_bridge_bot": true,
		})
	}
}

func (br *Bridge) loadConfig() {
	configData, upgraded, err := configupgrade.Do(br.ConfigPath, br.SaveConfig, br.ConfigUpgrader)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Error updating config:", err)
		if configData == nil {
			os.Exit(10)
		}
	}

	target := br.Child.GetConfigPtr()
	if !upgraded {
		// Fallback: if config upgrading failed, load example config for base values
		err = yaml.Unmarshal([]byte(br.Child.GetExampleConfig()), &target)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Failed to unmarshal example config:", err)
			os.Exit(10)
		}
	}
	err = yaml.Unmarshal(configData, target)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to parse config:", err)
		os.Exit(10)
	}
}

func (br *Bridge) validateConfig() error {
	switch {
	case br.Config.Homeserver.Address == "https://matrix.example.com":
		return errors.New("homeserver.address not configured")
	case br.Config.Homeserver.Domain == "example.com":
		return errors.New("homeserver.domain not configured")
	case !bridgeconfig.AllowedHomeserverSoftware[br.Config.Homeserver.Software]:
		return errors.New("invalid value for homeserver.software (use `standard` if you don't know what the field is for)")
	case br.Config.AppService.ASToken == "This value is generated when generating the registration":
		return errors.New("appservice.as_token not configured. Did you forget to generate the registration? ")
	case br.Config.AppService.HSToken == "This value is generated when generating the registration":
		return errors.New("appservice.hs_token not configured. Did you forget to generate the registration? ")
	case br.Config.AppService.Database.URI == "postgres://user:password@host/database?sslmode=disable":
		return errors.New("appservice.database not configured")
	default:
		err := br.Config.Bridge.Validate()
		if err != nil {
			return err
		}
		validator, ok := br.Child.(ConfigValidatingBridge)
		if ok {
			return validator.ValidateConfig()
		}
		return nil
	}
}

func (br *Bridge) getProfile(userID id.UserID, roomID id.RoomID) *event.MemberEventContent {
	ghost := br.Child.GetIGhost(userID)
	if ghost == nil {
		return nil
	}
	profilefulGhost, ok := ghost.(GhostWithProfile)
	if ok {
		return &event.MemberEventContent{
			Displayname: profilefulGhost.GetDisplayname(),
			AvatarURL:   profilefulGhost.GetAvatarURL().CUString(),
		}
	}
	return nil
}

func (br *Bridge) init() {
	pib, ok := br.Child.(PreInitableBridge)
	if ok {
		pib.PreInit()
	}

	var err error

	br.MediaConfig.UploadSize = 50 * 1024 * 1024

	br.ZLog, err = br.Config.Logging.Compile()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to initialize logger:", err)
		os.Exit(12)
	}
	exzerolog.SetupDefaults(br.ZLog)
	br.Log = maulogadapt.ZeroAsMau(br.ZLog)

	br.DoublePuppet = &doublePuppetUtil{br: br, log: br.ZLog.With().Str("component", "double puppet").Logger()}

	err = br.validateConfig()
	if err != nil {
		br.ZLog.WithLevel(zerolog.FatalLevel).Err(err).Msg("Configuration error")
		os.Exit(11)
	}

	br.ZLog.Info().
		Str("name", br.Name).
		Str("version", br.Version).
		Str("built_at", br.BuildTime).
		Str("go_version", runtime.Version()).
		Msg("Initializing bridge")

	br.ZLog.Debug().Msg("Initializing database connection")
	dbConfig := br.Config.AppService.Database
	if (dbConfig.Type == "sqlite3-fk-wal" || dbConfig.Type == "litestream") && dbConfig.MaxOpenConns != 1 && !strings.Contains(dbConfig.URI, "_txlock=immediate") {
		var fixedExampleURI string
		if !strings.HasPrefix(dbConfig.URI, "file:") {
			fixedExampleURI = fmt.Sprintf("file:%s?_txlock=immediate", dbConfig.URI)
		} else if !strings.ContainsRune(dbConfig.URI, '?') {
			fixedExampleURI = fmt.Sprintf("%s?_txlock=immediate", dbConfig.URI)
		} else {
			fixedExampleURI = fmt.Sprintf("%s&_txlock=immediate", dbConfig.URI)
		}
		br.ZLog.Warn().
			Str("fixed_uri_example", fixedExampleURI).
			Msg("Using SQLite without _txlock=immediate is not recommended")
	}
	br.DB, err = dbutil.NewFromConfig(br.Name, dbConfig, dbutil.ZeroLogger(br.ZLog.With().Str("db_section", "main").Logger()))
	if err != nil {
		br.ZLog.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to initialize database connection")
		if sqlError := (&sqlite3.Error{}); errors.As(err, sqlError) && sqlError.Code == sqlite3.ErrCorrupt {
			os.Exit(18)
		}
		os.Exit(14)
	}
	br.DB.IgnoreUnsupportedDatabase = *ignoreUnsupportedDatabase
	br.DB.IgnoreForeignTables = *ignoreForeignTables

	br.ZLog.Debug().Msg("Initializing state store")
	br.StateStore = sqlstatestore.NewSQLStateStore(br.DB, dbutil.ZeroLogger(br.ZLog.With().Str("db_section", "matrix_state").Logger()), true)

	br.AS, err = appservice.CreateFull(appservice.CreateOpts{
		Registration:     br.Config.AppService.GetRegistration(),
		HomeserverDomain: br.Config.Homeserver.Domain,
		HomeserverURL:    br.Config.Homeserver.Address,
		HostConfig: appservice.HostConfig{
			Hostname: br.Config.AppService.Hostname,
			Port:     br.Config.AppService.Port,
		},
		StateStore: br.StateStore,
	})
	if err != nil {
		br.ZLog.WithLevel(zerolog.FatalLevel).Err(err).
			Msg("Failed to initialize appservice")
		os.Exit(15)
	}
	br.AS.Log = *br.ZLog
	br.AS.DoublePuppetValue = br.Name
	br.AS.GetProfile = br.getProfile
	br.Bot = br.AS.BotIntent()

	br.ZLog.Debug().Msg("Initializing Matrix event processor")
	br.EventProcessor = appservice.NewEventProcessor(br.AS)
	if !br.Config.AppService.AsyncTransactions {
		br.EventProcessor.ExecMode = appservice.Sync
	}
	br.ZLog.Debug().Msg("Initializing Matrix event handler")
	br.MatrixHandler = NewMatrixHandler(br)

	br.Crypto = NewCryptoHelper(br)

	hsURL := br.Config.Homeserver.Address
	if br.Config.Homeserver.PublicAddress != "" {
		hsURL = br.Config.Homeserver.PublicAddress
	}
	br.PublicHSAddress, err = url.Parse(hsURL)
	if err != nil {
		br.ZLog.WithLevel(zerolog.FatalLevel).Err(err).
			Str("input", hsURL).
			Msg("Failed to parse public homeserver URL")
		os.Exit(15)
	}

	br.Child.Init()
}

type zerologPQError pq.Error

func (zpe *zerologPQError) MarshalZerologObject(evt *zerolog.Event) {
	maybeStr := func(field, value string) {
		if value != "" {
			evt.Str(field, value)
		}
	}
	maybeStr("severity", zpe.Severity)
	if name := zpe.Code.Name(); name != "" {
		evt.Str("code", name)
	} else if zpe.Code != "" {
		evt.Str("code", string(zpe.Code))
	}
	//maybeStr("message", zpe.Message)
	maybeStr("detail", zpe.Detail)
	maybeStr("hint", zpe.Hint)
	maybeStr("position", zpe.Position)
	maybeStr("internal_position", zpe.InternalPosition)
	maybeStr("internal_query", zpe.InternalQuery)
	maybeStr("where", zpe.Where)
	maybeStr("schema", zpe.Schema)
	maybeStr("table", zpe.Table)
	maybeStr("column", zpe.Column)
	maybeStr("data_type_name", zpe.DataTypeName)
	maybeStr("constraint", zpe.Constraint)
	maybeStr("file", zpe.File)
	maybeStr("line", zpe.Line)
	maybeStr("routine", zpe.Routine)
}

func (br *Bridge) LogDBUpgradeErrorAndExit(name string, err error) {
	logEvt := br.ZLog.WithLevel(zerolog.FatalLevel).
		Err(err).
		Str("db_section", name)
	var errWithLine *dbutil.PQErrorWithLine
	if errors.As(err, &errWithLine) {
		logEvt.Str("sql_line", errWithLine.Line)
	}
	var pqe *pq.Error
	if errors.As(err, &pqe) {
		logEvt.Object("pq_error", (*zerologPQError)(pqe))
	}
	logEvt.Msg("Failed to initialize database")
	if sqlError := (&sqlite3.Error{}); errors.As(err, sqlError) && sqlError.Code == sqlite3.ErrCorrupt {
		os.Exit(18)
	} else if errors.Is(err, dbutil.ErrForeignTables) {
		br.ZLog.Info().Msg("You can use --ignore-foreign-tables to ignore this error")
	} else if errors.Is(err, dbutil.ErrNotOwned) {
		br.ZLog.Info().Msg("Sharing the same database with different programs is not supported")
	} else if errors.Is(err, dbutil.ErrUnsupportedDatabaseVersion) {
		br.ZLog.Info().Msg("Downgrading the bridge is not supported")
	}
	os.Exit(15)
}

func (br *Bridge) WaitWebsocketConnected() {
	if br.wsStartupWait != nil {
		br.wsStartupWait.Wait()
	}
}

func (br *Bridge) start() {
	br.ZLog.Debug().Msg("Running database upgrades")
	err := br.DB.Upgrade(br.ZLog.With().Str("db_section", "main").Logger().WithContext(context.TODO()))
	if err != nil {
		br.LogDBUpgradeErrorAndExit("main", err)
	} else if err = br.StateStore.Upgrade(br.ZLog.With().Str("db_section", "matrix_state").Logger().WithContext(context.TODO())); err != nil {
		br.LogDBUpgradeErrorAndExit("matrix_state", err)
	}

	if br.Config.Homeserver.Websocket || len(br.Config.Homeserver.WSProxy) > 0 {
		br.Websocket = true
		br.ZLog.Debug().Msg("Starting application service websocket")
		var wg sync.WaitGroup
		wg.Add(1)
		br.wsStartupWait = &wg
		br.wsShortCircuitReconnectBackoff = make(chan struct{})
		go br.startWebsocket(&wg)
	} else if br.AS.Host.IsConfigured() {
		br.ZLog.Debug().Msg("Starting application service HTTP server")
		go br.AS.Start()
	} else {
		br.ZLog.WithLevel(zerolog.FatalLevel).Msg("Neither appservice HTTP listener nor websocket is enabled")
		os.Exit(23)
	}
	br.ZLog.Debug().Msg("Checking connection to homeserver")

	ctx := br.ZLog.WithContext(context.Background())
	br.ensureConnection(ctx)
	go br.fetchMediaConfig(ctx)

	if br.Crypto != nil {
		err = br.Crypto.Init(ctx)
		if err != nil {
			br.ZLog.WithLevel(zerolog.FatalLevel).Err(err).Msg("Error initializing end-to-bridge encryption")
			os.Exit(19)
		}
	}

	br.ZLog.Debug().Msg("Starting event processor")
	br.EventProcessor.Start(ctx)

	go br.UpdateBotProfile(ctx)
	if br.Crypto != nil {
		go br.Crypto.Start()
	}

	br.Child.Start()
	br.WaitWebsocketConnected()
	br.AS.Ready = true

	if br.Config.Bridge.GetResendBridgeInfo() {
		go br.ResendBridgeInfo()
	}
	if br.Websocket && br.Config.Homeserver.WSPingInterval > 0 {
		br.wsStopPinger = make(chan struct{}, 1)
		go br.websocketServerPinger()
	}
}

func (br *Bridge) ResendBridgeInfo() {
	if !br.SaveConfig {
		br.ZLog.Warn().Msg("Not setting resend_bridge_info to false in config due to --no-update flag")
	} else {
		_, _, err := configupgrade.Do(br.ConfigPath, true, br.ConfigUpgrader, configupgrade.SimpleUpgrader(func(helper *configupgrade.Helper) {
			helper.Set(configupgrade.Bool, "false", "bridge", "resend_bridge_info")
		}))
		if err != nil {
			br.ZLog.Err(err).Msg("Failed to save config after setting resend_bridge_info to false")
		}
	}
	br.ZLog.Info().Msg("Re-sending bridge info state event to all portals")
	for _, portal := range br.Child.GetAllIPortals() {
		portal.UpdateBridgeInfo(context.TODO())
	}
	br.ZLog.Info().Msg("Finished re-sending bridge info state events")
}

func sendStopSignal(ch chan struct{}) {
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (br *Bridge) stop() {
	br.Stopping = true
	if br.Crypto != nil {
		br.Crypto.Stop()
	}
	waitForWS := false
	if br.AS.StopWebsocket != nil {
		br.ZLog.Debug().Msg("Stopping application service websocket")
		br.AS.StopWebsocket(appservice.ErrWebsocketManualStop)
		waitForWS = true
	}
	br.AS.Stop()
	sendStopSignal(br.wsStopPinger)
	sendStopSignal(br.wsShortCircuitReconnectBackoff)
	br.EventProcessor.Stop()
	br.Child.Stop()
	err := br.DB.Close()
	if err != nil {
		br.ZLog.Warn().Err(err).Msg("Error closing database")
	}
	if waitForWS {
		select {
		case <-br.wsStopped:
		case <-time.After(4 * time.Second):
			br.ZLog.Warn().Msg("Timed out waiting for websocket to close")
		}
	}
}

func (br *Bridge) ManualStop(exitCode int) {
	if br.manualStop != nil {
		br.manualStop <- exitCode
	} else {
		os.Exit(exitCode)
	}
}

type VersionJSONOutput struct {
	Name string
	URL  string

	Version          string
	IsRelease        bool
	Commit           string
	FormattedVersion string
	BuildTime        string

	OS   string
	Arch string

	Mautrix struct {
		Version string
		Commit  string
	}
}

func (br *Bridge) Main() {
	flag.SetHelpTitles(
		fmt.Sprintf("%s - %s", br.Name, br.Description),
		fmt.Sprintf("%s [-hgvn%s] [-c <path>] [-r <path>]%s", br.Name, br.AdditionalShortFlags, br.AdditionalLongFlags))
	err := flag.Parse()
	br.ConfigPath = *configPath
	br.RegistrationPath = *registrationPath
	br.SaveConfig = !*dontSaveConfig
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		flag.PrintHelp()
		os.Exit(1)
	} else if *wantHelp {
		flag.PrintHelp()
		os.Exit(0)
	} else if *version {
		fmt.Println(br.VersionDesc)
		return
	} else if *versionJSON {
		output := VersionJSONOutput{
			URL:  br.URL,
			Name: br.Name,

			Version:          br.baseVersion,
			IsRelease:        br.Version == br.baseVersion,
			Commit:           br.commit,
			FormattedVersion: br.Version,
			BuildTime:        br.BuildTime,

			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		}
		output.Mautrix.Commit = mautrix.Commit
		output.Mautrix.Version = mautrix.Version
		_ = json.NewEncoder(os.Stdout).Encode(output)
		return
	} else if flagHandler, ok := br.Child.(FlagHandlingBridge); ok && flagHandler.HandleFlags() {
		return
	}

	br.loadConfig()

	if *generateRegistration {
		br.GenerateRegistration()
		return
	}

	br.manualStop = make(chan int, 1)
	br.init()
	br.ZLog.Info().Msg("Bridge initialization complete, starting...")
	br.start()
	br.ZLog.Info().Msg("Bridge started!")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	var exitCode int
	select {
	case <-c:
		br.ZLog.Info().Msg("Interrupt received, stopping...")
	case exitCode = <-br.manualStop:
		br.ZLog.Info().Int("exit_code", exitCode).Msg("Manual stop requested")
	}

	br.stop()
	br.ZLog.Info().Msg("Bridge stopped.")
	os.Exit(exitCode)
}
