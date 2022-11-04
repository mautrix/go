// Copyright (c) 2022 Tulir Asokan
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
	"gopkg.in/yaml.v3"
	flag "maunium.net/go/mauflag"
	log "maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/appservice/sqlstatestore"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
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
	Log              log.Logger
	DB               *dbutil.Database
	StateStore       *sqlstatestore.SQLStateStore
	Crypto           Crypto
	CryptoPickleKey  string

	MediaConfig mautrix.RespMediaConfig

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
			br.Log.Errorfln("Failed to connect to homeserver: %v. Retrying in 10 seconds...", err)
			time.Sleep(10 * time.Second)
			continue
		}
		if br.Config.Homeserver.Software == bridgeconfig.SoftwareHungry && !versions.UnstableFeatures["com.beeper.hungry"] {
			br.Log.Fatalln("The config claims the homeserver is hungryserv, but the /versions response didn't confirm it")
			os.Exit(18)
		} else if !versions.ContainsGreaterOrEqual(MinSpecVersion) {
			br.Log.Fatalfln("The homeserver is outdated (server supports %s, but the bridge requires at least %s)", versions.GetLatest(), MinSpecVersion)
			os.Exit(18)
		} else if fr, ok := br.Child.(CSFeatureRequirer); ok {
			if msg, hasFeatures := fr.CheckFeatures(versions); !hasFeatures {
				br.Log.Fatalln(msg)
				os.Exit(18)
			}
		}

		resp, err := br.Bot.Whoami()
		if err != nil {
			if errors.Is(err, mautrix.MUnknownToken) {
				br.Log.Fatalln("The as_token was not accepted. Is the registration file installed in your homeserver correctly?")
				os.Exit(16)
			} else if errors.Is(err, mautrix.MExclusive) {
				br.Log.Fatalln("The as_token was accepted, but the /register request was not. Are the homeserver domain and username template in the config correct, and do they match the values in the registration?")
				os.Exit(16)
			}
			br.Log.Errorfln("Failed to connect to homeserver: %v. Retrying in 10 seconds...", err)
			time.Sleep(10 * time.Second)
		} else if resp.UserID != br.Bot.UserID {
			br.Log.Fatalln("Unexpected user ID in whoami call: got %s, expected %s", resp.UserID, br.Bot.UserID)
			os.Exit(17)
		} else {
			break
		}
	}
}

func (br *Bridge) fetchMediaConfig() {
	cfg, err := br.Bot.GetMediaConfig()
	if err != nil {
		br.Log.Warnfln("Failed to fetch media config: %v", err)
	} else {
		br.MediaConfig = *cfg
	}
}

func (br *Bridge) UpdateBotProfile() {
	br.Log.Debugln("Updating bot profile")
	botConfig := &br.Config.AppService.Bot

	var err error
	var mxc id.ContentURI
	if botConfig.Avatar == "remove" {
		err = br.Bot.SetAvatarURL(mxc)
	} else if !botConfig.ParsedAvatar.IsEmpty() {
		err = br.Bot.SetAvatarURL(botConfig.ParsedAvatar)
	}
	if err != nil {
		br.Log.Warnln("Failed to update bot avatar:", err)
	}

	if botConfig.Displayname == "remove" {
		err = br.Bot.SetDisplayName("")
	} else if len(botConfig.Displayname) > 0 {
		err = br.Bot.SetDisplayName(botConfig.Displayname)
	}
	if err != nil {
		br.Log.Warnln("Failed to update bot displayname:", err)
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
	case br.Config.Homeserver.Address == "https://example.com":
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

	br.AS = br.Config.MakeAppService()
	br.AS.DoublePuppetValue = br.Name
	br.AS.GetProfile = br.getProfile
	_, _ = br.AS.Init()

	if br.Log == nil {
		br.Log = log.Create()
	}
	br.Config.Logging.Configure(br.Log)
	log.DefaultLogger = br.Log.(*log.BasicLogger)
	if len(br.Config.Logging.FileNameFormat) > 0 {
		err = log.OpenFile()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Failed to open log file:", err)
			os.Exit(12)
		}
	}

	err = br.validateConfig()
	if err != nil {
		br.Log.Fatalln("Configuration error:", err)
		os.Exit(11)
	}

	br.AS.Log = log.Sub("Matrix")
	br.Bot = br.AS.BotIntent()
	br.Log.Infoln("Initializing", br.VersionDesc)

	br.Log.Debugln("Initializing database connection")
	br.DB, err = dbutil.NewFromConfig(br.Name, br.Config.AppService.Database, dbutil.MauLogger(br.Log.Sub("Database")))
	if err != nil {
		br.Log.Fatalln("Failed to initialize database connection:", err)
		if sqlError := (&sqlite3.Error{}); errors.As(err, sqlError) && sqlError.Code == sqlite3.ErrCorrupt {
			os.Exit(18)
		}
		os.Exit(14)
	}
	br.DB.IgnoreUnsupportedDatabase = *ignoreUnsupportedDatabase
	br.DB.IgnoreForeignTables = *ignoreForeignTables

	br.Log.Debugln("Initializing state store")
	br.StateStore = sqlstatestore.NewSQLStateStore(br.DB, dbutil.MauLogger(br.Log.Sub("Database").Sub("StateStore")))
	br.AS.StateStore = br.StateStore

	br.Log.Debugln("Initializing Matrix event processor")
	br.EventProcessor = appservice.NewEventProcessor(br.AS)
	br.EventProcessor.ExecMode = appservice.Sync
	br.Log.Debugln("Initializing Matrix event handler")
	br.MatrixHandler = NewMatrixHandler(br)

	br.Crypto = NewCryptoHelper(br)

	br.Child.Init()
}

func (br *Bridge) LogDBUpgradeErrorAndExit(name string, err error) {
	br.Log.Fatalfln("Failed to initialize %s: %v", name, err)
	if sqlError := (&sqlite3.Error{}); errors.As(err, sqlError) && sqlError.Code == sqlite3.ErrCorrupt {
		os.Exit(18)
	} else if errors.Is(err, dbutil.ErrForeignTables) {
		br.Log.Infoln("You can use --ignore-foreign-tables to ignore this error")
	} else if errors.Is(err, dbutil.ErrNotOwned) {
		br.Log.Infoln("Sharing the same database with different programs is not supported")
	} else if errors.Is(err, dbutil.ErrUnsupportedDatabaseVersion) {
		br.Log.Infoln("Downgrading the bridge is not supported")
	}
	os.Exit(15)
}

func (br *Bridge) start() {
	br.Log.Debugln("Running database upgrades")
	err := br.DB.Upgrade()
	if err != nil {
		br.LogDBUpgradeErrorAndExit("main database", err)
	} else if err = br.StateStore.Upgrade(); err != nil {
		br.LogDBUpgradeErrorAndExit("matrix state store", err)
	}

	br.Log.Debugln("Checking connection to homeserver")
	br.ensureConnection()
	go br.fetchMediaConfig()

	if br.Crypto != nil {
		err = br.Crypto.Init()
		if err != nil {
			br.Log.Fatalln("Error initializing end-to-bridge encryption:", err)
			os.Exit(19)
		}
	}

	br.Log.Debugln("Starting application service HTTP server")
	go br.AS.Start()
	br.Log.Debugln("Starting event processor")
	go br.EventProcessor.Start()

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
		br.Log.Warnln("Not setting resend_bridge_info to false in config due to --no-update flag")
	} else {
		_, _, err := configupgrade.Do(br.ConfigPath, true, br.ConfigUpgrader, configupgrade.SimpleUpgrader(func(helper *configupgrade.Helper) {
			helper.Set(configupgrade.Bool, "false", "bridge", "resend_bridge_info")
		}))
		if err != nil {
			br.Log.Errorln("Failed to save config after setting resend_bridge_info to false:", err)
		}
	}
	br.Log.Infoln("Re-sending bridge info state event to all portals")
	for _, portal := range br.Child.GetAllIPortals() {
		portal.UpdateBridgeInfo()
	}
	br.Log.Infoln("Finished re-sending bridge info state events")
}

func (br *Bridge) stop() {
	if br.Crypto != nil {
		br.Crypto.Stop()
	}
	br.AS.Stop()
	br.EventProcessor.Stop()
	br.Child.Stop()
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
	br.Log.Infoln("Bridge initialization complete, starting...")
	br.start()
	br.Log.Infoln("Bridge started!")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	var exitCode int
	select {
	case <-c:
		br.Log.Infoln("Interrupt received, stopping...")
	case exitCode = <-br.manualStop:
		br.Log.Infofln("Manual stop with code %d requested", exitCode)
	}

	br.stop()
	br.Log.Infoln("Bridge stopped.")
	os.Exit(exitCode)
}
