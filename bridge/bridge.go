// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridge

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
	flag "maunium.net/go/mauflag"
	"maunium.net/go/maulogger/v2"
	"maunium.net/go/maulogger/v2/maulogadapt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/sqlstatestore"
	"maunium.net/go/mautrix/util/configupgrade"
	"maunium.net/go/mautrix/util/dbutil"
	_ "maunium.net/go/mautrix/util/dbutil/litestream"
)

var configPath = flag.MakeFull("c", "config", "The path to your config file.", "config.yaml").String()
var dontSaveConfig = flag.MakeFull("n", "no-update", "Don't save updated config to disk.", "false").Bool()
var registrationPath = flag.MakeFull("r", "registration", "The path where to save the appservice registration.", "registration.yaml").String()
var generateRegistration = flag.MakeFull("g", "generate-registration", "Generate registration and quit.", "false").Bool()
var version = flag.MakeFull("v", "version", "View bridge version and quit.", "false").Bool()
var ignoreUnsupportedDatabase = flag.Make().LongKey("ignore-unsupported-database").Usage("Run even if the database schema is too new").Default("false").Bool()
var ignoreForeignTables = flag.Make().LongKey("ignore-foreign-tables").Usage("Run even if the database contains tables from other programs (like Synapse)").Default("false").Bool()
var wantHelp, _ = flag.MakeHelpFlag()

var _ appservice.StateStore = (*sqlstatestore.SQLStateStore)(nil)
var _ crypto.StateStore = (*sqlstatestore.SQLStateStore)(nil)

type Portal interface {
	IsEncrypted() bool
	IsPrivateChat() bool
	MarkEncrypted()
	MainIntent() *appservice.IntentAPI

	ReceiveMatrixEvent(user User, evt *event.Event)
	UpdateBridgeInfo()
}

type MembershipHandlingPortal interface {
	Portal
	HandleMatrixLeave(sender User)
	HandleMatrixKick(sender User, ghost Ghost)
	HandleMatrixInvite(sender User, ghost Ghost)
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

type FlagHandlingBridge interface {
	ChildOverride
	HandleFlags() bool
}

type PreInitableBridge interface {
	ChildOverride
	PreInit()
}

type CSFeatureRequirer interface {
	CheckFeatures(versions *mautrix.RespVersions) (string, bool)
}

type Bridge struct {
	Name         string
	URL          string
	Description  string
	Version      string
	ProtocolName string

	AdditionalShortFlags string
	AdditionalLongFlags  string

	VersionDesc      string
	LinkifiedVersion string
	BuildTime        string

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
}

type Crypto interface {
	HandleMemberEvent(*event.Event)
	Decrypt(*event.Event) (*event.Event, error)
	Encrypt(id.RoomID, event.Type, *event.Content) error
	WaitForSession(id.RoomID, id.SenderKey, id.SessionID, time.Duration) bool
	RequestSession(id.RoomID, id.SenderKey, id.SessionID, id.UserID, id.DeviceID)
	ResetSession(id.RoomID)
	Init() error
	Start()
	Stop()
	Reset(startAfterReset bool)
	Client() *mautrix.Client
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
	br.BuildTime = buildTime
}

var MinSpecVersion = mautrix.SpecV11

func (br *Bridge) ensureConnection() {
	for {
		versions, err := br.Bot.Versions()
		if err != nil {
			br.ZLog.Err(err).Msg("Failed to connect to homeserver, retrying in 10 seconds...")
			time.Sleep(10 * time.Second)
			continue
		}
		br.SpecVersions = *versions
		if br.Config.Homeserver.Software == bridgeconfig.SoftwareHungry && !versions.UnstableFeatures["com.beeper.hungry"] {
			br.ZLog.WithLevel(zerolog.FatalLevel).Msg("The config claims the homeserver is hungryserv, but the /versions response didn't confirm it")
			os.Exit(18)
		} else if !versions.ContainsGreaterOrEqual(MinSpecVersion) {
			br.ZLog.WithLevel(zerolog.FatalLevel).
				Stringer("server_supports", versions.GetLatest()).
				Stringer("bridge_requires", MinSpecVersion).
				Msg("The homeserver is outdated (supported spec versions are below minimum required by bridge)")
			os.Exit(18)
		} else if fr, ok := br.Child.(CSFeatureRequirer); ok {
			if msg, hasFeatures := fr.CheckFeatures(versions); !hasFeatures {
				br.ZLog.WithLevel(zerolog.FatalLevel).Msg(msg)
				os.Exit(18)
			}
		}

		resp, err := br.Bot.Whoami()
		if err != nil {
			if errors.Is(err, mautrix.MUnknownToken) {
				br.ZLog.WithLevel(zerolog.FatalLevel).Msg("The as_token was not accepted. Is the registration file installed in your homeserver correctly?")
				os.Exit(16)
			} else if errors.Is(err, mautrix.MExclusive) {
				br.ZLog.WithLevel(zerolog.FatalLevel).Msg("The as_token was accepted, but the /register request was not. Are the homeserver domain and username template in the config correct, and do they match the values in the registration?")
				os.Exit(16)
			}
			br.ZLog.Err(err).Msg("Failed to connect to homeserver, retrying in 10 seconds...")
			time.Sleep(10 * time.Second)
		} else if resp.UserID != br.Bot.UserID {
			br.ZLog.WithLevel(zerolog.FatalLevel).
				Stringer("got_user_id", resp.UserID).
				Stringer("expected_user_id", br.Bot.UserID).
				Msg("Unexpected user ID in whoami call")
			os.Exit(17)
		} else {
			break
		}
	}
}

func (br *Bridge) fetchMediaConfig() {
	cfg, err := br.Bot.GetMediaConfig()
	if err != nil {
		br.ZLog.Warn().Err(err).Msg("Failed to fetch media config")
	} else {
		br.MediaConfig = *cfg
	}
}

func (br *Bridge) UpdateBotProfile() {
	br.ZLog.Debug().Msg("Updating bot profile")
	botConfig := &br.Config.AppService.Bot

	var err error
	var mxc id.ContentURI
	if botConfig.Avatar == "remove" {
		err = br.Bot.SetAvatarURL(mxc)
	} else if !botConfig.ParsedAvatar.IsEmpty() {
		err = br.Bot.SetAvatarURL(botConfig.ParsedAvatar)
	}
	if err != nil {
		br.ZLog.Warn().Err(err).Msg("Failed to update bot avatar")
	}

	if botConfig.Displayname == "remove" {
		err = br.Bot.SetDisplayName("")
	} else if len(botConfig.Displayname) > 0 {
		err = br.Bot.SetDisplayName(botConfig.Displayname)
	}
	if err != nil {
		br.ZLog.Warn().Err(err).Msg("Failed to update bot displayname")
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
		return br.Config.Bridge.Validate()
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
	defaultCtxLog := br.ZLog.With().Bool("default_context_log", true).Caller().Logger()
	zerolog.DefaultContextLogger = &defaultCtxLog
	br.Log = maulogadapt.ZeroAsMau(br.ZLog)

	br.AS = br.Config.MakeAppService()
	br.AS.DoublePuppetValue = br.Name
	br.AS.GetProfile = br.getProfile
	br.AS.Log = *br.ZLog
	br.AS.LogConfig = nil
	_, _ = br.AS.Init()

	err = br.validateConfig()
	if err != nil {
		br.ZLog.WithLevel(zerolog.FatalLevel).Err(err).Msg("Configuration error")
		os.Exit(11)
	}

	br.Bot = br.AS.BotIntent()
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
	br.StateStore = sqlstatestore.NewSQLStateStore(br.DB, dbutil.ZeroLogger(br.ZLog.With().Str("db_section", "matrix_state").Logger()))
	br.AS.StateStore = br.StateStore

	br.ZLog.Debug().Msg("Initializing Matrix event processor")
	br.EventProcessor = appservice.NewEventProcessor(br.AS)
	if !br.Config.AppService.AsyncTransactions {
		br.EventProcessor.ExecMode = appservice.Sync
	}
	br.ZLog.Debug().Msg("Initializing Matrix event handler")
	br.MatrixHandler = NewMatrixHandler(br)

	br.Crypto = NewCryptoHelper(br)

	br.Child.Init()
}

func (br *Bridge) LogDBUpgradeErrorAndExit(name string, err error) {
	br.ZLog.WithLevel(zerolog.FatalLevel).
		Err(err).
		Str("db_section", name).
		Msg("Failed to initialize database")
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

func (br *Bridge) start() {
	br.ZLog.Debug().Msg("Running database upgrades")
	err := br.DB.Upgrade()
	if err != nil {
		br.LogDBUpgradeErrorAndExit("main", err)
	} else if err = br.StateStore.Upgrade(); err != nil {
		br.LogDBUpgradeErrorAndExit("matrix_state", err)
	}

	br.ZLog.Debug().Msg("Checking connection to homeserver")
	br.ensureConnection()
	go br.fetchMediaConfig()

	if br.Crypto != nil {
		err = br.Crypto.Init()
		if err != nil {
			br.ZLog.WithLevel(zerolog.FatalLevel).Err(err).Msg("Error initializing end-to-bridge encryption")
			os.Exit(19)
		}
	}

	if br.AS.Host.Port != 0 {
		br.ZLog.Debug().Msg("Starting application service HTTP server")
		go br.AS.Start()
	} else {
		br.ZLog.Debug().Msg("Appservice port not configured, not starting HTTP server")
	}
	br.ZLog.Debug().Msg("Starting event processor")
	br.EventProcessor.Start()

	go br.UpdateBotProfile()
	if br.Crypto != nil {
		go br.Crypto.Start()
	}

	br.Child.Start()
	br.AS.Ready = true

	if br.Config.Bridge.GetResendBridgeInfo() {
		go br.ResendBridgeInfo()
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
		portal.UpdateBridgeInfo()
	}
	br.ZLog.Info().Msg("Finished re-sending bridge info state events")
}

func (br *Bridge) stop() {
	if br.Crypto != nil {
		br.Crypto.Stop()
	}
	br.AS.Stop()
	br.EventProcessor.Stop()
	br.Child.Stop()
	err := br.DB.RawDB.Close()
	if err != nil {
		br.ZLog.Warn().Err(err).Msg("Error closing database")
	}
}

func (br *Bridge) ManualStop(exitCode int) {
	if br.manualStop != nil {
		br.manualStop <- exitCode
	} else {
		os.Exit(exitCode)
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
