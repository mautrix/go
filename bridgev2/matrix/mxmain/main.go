// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package mxmain contains initialization code for a single-network Matrix bridge using the bridgev2 package.
package mxmain

import (
	"context"
	_ "embed"
	"encoding/json"
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
	"go.mau.fi/util/configupgrade"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exzerolog"
	"gopkg.in/yaml.v3"
	flag "maunium.net/go/mauflag"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/commands"
	"maunium.net/go/mautrix/bridgev2/matrix"
)

var configPath = flag.MakeFull("c", "config", "The path to your config file.", "config.yaml").String()
var writeExampleConfig = flag.MakeFull("e", "generate-example-config", "Save the example config to the config path and quit.", "false").Bool()
var dontSaveConfig = flag.MakeFull("n", "no-update", "Don't save updated config to disk.", "false").Bool()
var registrationPath = flag.MakeFull("r", "registration", "The path where to save the appservice registration.", "registration.yaml").String()
var generateRegistration = flag.MakeFull("g", "generate-registration", "Generate registration and quit.", "false").Bool()
var version = flag.MakeFull("v", "version", "View bridge version and quit.", "false").Bool()
var versionJSON = flag.Make().LongKey("version-json").Usage("Print a JSON object representing the bridge version and quit.").Default("false").Bool()
var ignoreUnsupportedDatabase = flag.Make().LongKey("ignore-unsupported-database").Usage("Run even if the database schema is too new").Default("false").Bool()
var ignoreForeignTables = flag.Make().LongKey("ignore-foreign-tables").Usage("Run even if the database contains tables from other programs (like Synapse)").Default("false").Bool()
var ignoreUnsupportedServer = flag.Make().LongKey("ignore-unsupported-server").Usage("Run even if the Matrix homeserver is outdated").Default("false").Bool()
var wantHelp, _ = flag.MakeHelpFlag()

// BridgeMain contains the main function for a Matrix bridge.
type BridgeMain struct {
	// Name is the name of the bridge project, e.g. mautrix-signal.
	// Note that when making your own bridges that isn't under github.com/mautrix,
	// you should invent your own name and not use the mautrix-* naming scheme.
	Name string
	// Description is a brief description of the bridge, usually of the form "A Matrix-OtherPlatform puppeting bridge."
	Description string
	// URL is the Git repository address for the bridge.
	URL string
	// Version is the latest release of the bridge. InitVersion will compare this to the provided
	// git tag to see if the built version is the release or a dev build.
	// You can either bump this right after a release or right before, as long as it matches on the release commit.
	Version string

	// PostInit is a function that will be called after the bridge has been initialized but before it is started.
	PostInit  func()
	PostStart func()

	// PostMigratePortal is a function that will be called during a legacy
	// migration for each portal.
	PostMigratePortal func(context.Context, *bridgev2.Portal) error

	// Connector is the network connector for the bridge.
	Connector bridgev2.NetworkConnector

	// All fields below are set automatically in Run or InitVersion should not be set manually.

	Log    *zerolog.Logger
	DB     *dbutil.Database
	Config *bridgeconfig.Config
	Matrix *matrix.Connector
	Bridge *bridgev2.Bridge

	ConfigPath       string
	RegistrationPath string
	SaveConfig       bool

	baseVersion      string
	commit           string
	LinkifiedVersion string
	VersionDesc      string
	BuildTime        time.Time

	AdditionalShortFlags string
	AdditionalLongFlags  string

	manualStop chan int
}

type VersionJSONOutput struct {
	Name string
	URL  string

	Version          string
	IsRelease        bool
	Commit           string
	FormattedVersion string
	BuildTime        time.Time

	OS   string
	Arch string

	Mautrix struct {
		Version string
		Commit  string
	}
}

// Run runs the bridge and waits for SIGTERM before stopping.
func (br *BridgeMain) Run() {
	br.PreInit()
	br.Init()
	br.Start()
	exitCode := br.WaitForInterrupt()
	br.Stop()
	os.Exit(exitCode)
}

// PreInit parses CLI flags and loads the config file. This is called by [Run] and does not need to be called manually.
//
// This also handles all flags that cause the bridge to exit immediately (e.g. `--version` and `--generate-registration`).
func (br *BridgeMain) PreInit() {
	br.manualStop = make(chan int, 1)
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
		os.Exit(0)
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
		os.Exit(0)
	} else if *writeExampleConfig {
		if *configPath != "-" && *configPath != "/dev/stdout" && *configPath != "/dev/stderr" {
			if _, err = os.Stat(*configPath); !errors.Is(err, os.ErrNotExist) {
				_, _ = fmt.Fprintln(os.Stderr, *configPath, "already exists, please remove it if you want to generate a new example")
				os.Exit(1)
			}
		}
		networkExample, _, _ := br.Connector.GetConfig()
		fullCfg := br.makeFullExampleConfig(networkExample)
		if *configPath == "-" {
			fmt.Print(fullCfg)
		} else {
			exerrors.PanicIfNotNil(os.WriteFile(*configPath, []byte(fullCfg), 0600))
			fmt.Println("Wrote example config to", *configPath)
		}
		os.Exit(0)
	}
	br.LoadConfig()
	if *generateRegistration {
		br.GenerateRegistration()
		os.Exit(0)
	}
}

func (br *BridgeMain) GenerateRegistration() {
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

	updateTokens := func(helper configupgrade.Helper) {
		helper.Set(configupgrade.Str, reg.AppToken, "appservice", "as_token")
		helper.Set(configupgrade.Str, reg.ServerToken, "appservice", "hs_token")
	}
	upgrader, _ := br.getConfigUpgrader()
	_, _, err = configupgrade.Do(br.ConfigPath, true, upgrader, configupgrade.SimpleUpgrader(updateTokens))
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to save config:", err)
		os.Exit(22)
	}
	fmt.Println("Registration generated. See https://docs.mau.fi/bridges/general/registering-appservices.html for instructions on installing the registration.")
	os.Exit(0)
}

// Init sets up logging, database connection and creates the Matrix connector and central Bridge struct.
// This is called by [Run] and does not need to be called manually.
func (br *BridgeMain) Init() {
	var err error
	br.Log, err = br.Config.Logging.Compile()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to initialize logger:", err)
		os.Exit(12)
	}
	exzerolog.SetupDefaults(br.Log)
	err = br.validateConfig()
	if err != nil {
		br.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Configuration error")
		br.Log.Info().Msg("See https://docs.mau.fi/faq/field-unconfigured for more info")
		os.Exit(11)
	}

	br.Log.Info().
		Str("name", br.Name).
		Str("version", br.Version).
		Time("built_at", br.BuildTime).
		Str("go_version", runtime.Version()).
		Msg("Initializing bridge")

	br.initDB()
	br.Matrix = matrix.NewConnector(br.Config)
	br.Matrix.OnWebsocketReplaced = func() {
		br.TriggerStop(0)
	}
	br.Matrix.IgnoreUnsupportedServer = *ignoreUnsupportedServer
	br.Bridge = bridgev2.NewBridge("", br.DB, *br.Log, &br.Config.Bridge, br.Matrix, br.Connector, commands.NewProcessor)
	br.Matrix.AS.DoublePuppetValue = br.Name
	br.Bridge.Commands.(*commands.Processor).AddHandler(&commands.FullHandler{
		Func: func(ce *commands.Event) {
			ce.Reply("[%s](%s) %s (%s)", br.Name, br.URL, br.LinkifiedVersion, br.BuildTime.Format(time.RFC1123))
		},
		Name: "version",
		Help: commands.HelpMeta{
			Section:     commands.HelpSectionGeneral,
			Description: "Get the bridge version.",
		},
	})
	if br.PostInit != nil {
		br.PostInit()
	}
}

func (br *BridgeMain) initDB() {
	br.Log.Debug().Msg("Initializing database connection")
	dbConfig := br.Config.Database
	if dbConfig.Type == "sqlite3" {
		br.Log.WithLevel(zerolog.FatalLevel).Msg("Invalid database type sqlite3. Use sqlite3-fk-wal instead.")
		os.Exit(14)
	}
	if (dbConfig.Type == "sqlite3-fk-wal" || dbConfig.Type == "litestream") && dbConfig.MaxOpenConns != 1 && !strings.Contains(dbConfig.URI, "_txlock=immediate") {
		var fixedExampleURI string
		if !strings.HasPrefix(dbConfig.URI, "file:") {
			fixedExampleURI = fmt.Sprintf("file:%s?_txlock=immediate", dbConfig.URI)
		} else if !strings.ContainsRune(dbConfig.URI, '?') {
			fixedExampleURI = fmt.Sprintf("%s?_txlock=immediate", dbConfig.URI)
		} else {
			fixedExampleURI = fmt.Sprintf("%s&_txlock=immediate", dbConfig.URI)
		}
		br.Log.Warn().
			Str("fixed_uri_example", fixedExampleURI).
			Msg("Using SQLite without _txlock=immediate is not recommended")
	}
	var err error
	br.DB, err = dbutil.NewFromConfig("megabridge/"+br.Name, dbConfig, dbutil.ZeroLogger(br.Log.With().Str("db_section", "main").Logger()))
	if err != nil {
		br.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to initialize database connection")
		if sqlError := (&sqlite3.Error{}); errors.As(err, sqlError) && sqlError.Code == sqlite3.ErrCorrupt {
			os.Exit(18)
		}
		os.Exit(14)
	}
	br.DB.IgnoreUnsupportedDatabase = *ignoreUnsupportedDatabase
	br.DB.IgnoreForeignTables = *ignoreForeignTables
}

func (br *BridgeMain) validateConfig() error {
	switch {
	case br.Config.Homeserver.Address == "http://example.localhost:8008":
		return errors.New("homeserver.address not configured")
	case br.Config.Homeserver.Domain == "example.com":
		return errors.New("homeserver.domain not configured")
	case !bridgeconfig.AllowedHomeserverSoftware[br.Config.Homeserver.Software]:
		return errors.New("invalid value for homeserver.software (use `standard` if you don't know what the field is for)")
	case br.Config.AppService.ASToken == "This value is generated when generating the registration":
		return errors.New("appservice.as_token not configured. Did you forget to generate the registration? ")
	case br.Config.AppService.HSToken == "This value is generated when generating the registration":
		return errors.New("appservice.hs_token not configured. Did you forget to generate the registration? ")
	case br.Config.Database.URI == "postgres://user:password@host/database?sslmode=disable":
		return errors.New("database.uri not configured")
	case !br.Config.Bridge.Permissions.IsConfigured():
		return errors.New("bridge.permissions not configured")
	case !strings.Contains(br.Config.AppService.FormatUsername("1234567890"), "1234567890"):
		return errors.New("username template is missing user ID placeholder")
	default:
		cfgValidator, ok := br.Connector.(bridgev2.ConfigValidatingNetwork)
		if ok {
			err := cfgValidator.ValidateConfig()
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func (br *BridgeMain) getConfigUpgrader() (configupgrade.BaseUpgrader, any) {
	networkExample, networkData, networkUpgrader := br.Connector.GetConfig()
	baseConfig := br.makeFullExampleConfig(networkExample)
	if networkUpgrader == nil {
		networkUpgrader = configupgrade.NoopUpgrader
	}
	networkUpgraderProxied := &configupgrade.ProxyUpgrader{Target: networkUpgrader, Prefix: []string{"network"}}
	upgrader := configupgrade.MergeUpgraders(baseConfig, networkUpgraderProxied, bridgeconfig.Upgrader)
	return upgrader, networkData
}

// LoadConfig upgrades and loads the config file.
// This is called by [Run] and does not need to be called manually.
func (br *BridgeMain) LoadConfig() {
	upgrader, networkData := br.getConfigUpgrader()
	configData, upgraded, err := configupgrade.Do(br.ConfigPath, br.SaveConfig, upgrader)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Error updating config:", err)
		if !upgraded {
			os.Exit(10)
		}
	}

	var cfg bridgeconfig.Config
	err = yaml.Unmarshal(configData, &cfg)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to parse config:", err)
		os.Exit(10)
	}
	if networkData != nil {
		err = cfg.Network.Decode(networkData)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Failed to parse network config:", err)
			os.Exit(10)
		}
	}
	cfg.Bridge.Backfill = cfg.Backfill
	br.Config = &cfg
}

// Start starts the bridge after everything has been initialized.
// This is called by [Run] and does not need to be called manually.
func (br *BridgeMain) Start() {
	ctx := br.Log.WithContext(context.Background())
	err := br.Bridge.StartConnectors(ctx)
	if err != nil {
		var dbUpgradeErr bridgev2.DBUpgradeError
		if errors.As(err, &dbUpgradeErr) {
			br.LogDBUpgradeErrorAndExit(dbUpgradeErr.Section, dbUpgradeErr.Err, "Failed to initialize database")
		} else {
			br.Log.Fatal().Err(err).Msg("Failed to start bridge")
		}
	}
	err = br.PostMigrate(ctx)
	if err != nil {
		br.Log.Fatal().Err(err).Msg("Failed to run post-migration updates")
	}
	err = br.Bridge.StartLogins(ctx)
	if err != nil {
		br.Log.Fatal().Err(err).Msg("Failed to start existing user logins")
	}
	br.Bridge.PostStart(ctx)
	if br.PostStart != nil {
		br.PostStart()
	}
}

// WaitForInterrupt waits for a SIGINT or SIGTERM signal.
func (br *BridgeMain) WaitForInterrupt() int {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	select {
	case <-c:
		br.Log.Info().Msg("Interrupt signal received from OS")
		return 0
	case exitCode := <-br.manualStop:
		br.Log.Info().Msg("Internal stop signal received")
		return exitCode
	}
}

func (br *BridgeMain) TriggerStop(exitCode int) {
	select {
	case br.manualStop <- exitCode:
	default:
	}
}

// Stop cleanly stops the bridge. This is called by [Run] and does not need to be called manually.
func (br *BridgeMain) Stop() {
	br.Bridge.StopWithTimeout(5 * time.Second)
}

// InitVersion formats the bridge version and build time nicely for things like
// the `version` bridge command on Matrix and the `--version` CLI flag.
//
// The values should generally be set by the build system. For example, assuming you have
//
//	var (
//		Tag       = "unknown"
//		Commit    = "unknown"
//		BuildTime = "unknown"
//	)
//
// in your main package, then you'd use the following ldflags to fill them appropriately:
//
//	go build -ldflags "-X main.Tag=$(git describe --exact-match --tags 2>/dev/null) -X main.Commit=$(git rev-parse HEAD) -X 'main.BuildTime=`date -Iseconds`'"
//
// You may additionally want to fill the mautrix-go version using another ldflag:
//
//	export MAUTRIX_VERSION=$(cat go.mod | grep 'maunium.net/go/mautrix ' | head -n1 | awk '{ print $2 }')
//	go build -ldflags "-X 'maunium.net/go/mautrix.GoModVersion=$MAUTRIX_VERSION'"
//
// (to use both at the same time, simply merge the ldflags into one, `-ldflags "-X '...' -X ..."`)
func (br *BridgeMain) InitVersion(tag, commit, rawBuildTime string) {
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
	var buildTime time.Time
	if rawBuildTime != "unknown" {
		buildTime, _ = time.Parse(time.RFC3339, rawBuildTime)
	}
	var builtWith string
	if buildTime.IsZero() {
		rawBuildTime = "unknown"
		builtWith = runtime.Version()
	} else {
		rawBuildTime = buildTime.Format(time.RFC1123)
		builtWith = fmt.Sprintf("built at %s with %s", rawBuildTime, runtime.Version())
	}
	mautrix.DefaultUserAgent = fmt.Sprintf("%s/%s %s", br.Name, br.Version, mautrix.DefaultUserAgent)
	br.VersionDesc = fmt.Sprintf("%s %s (%s)", br.Name, br.Version, builtWith)
	br.commit = commit
	br.BuildTime = buildTime
}
