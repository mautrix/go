// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mxmain

import (
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

type BridgeMain struct {
	Name        string
	Description string
	URL         string
	Version     string

	PostInit func()

	Connector bridgev2.NetworkConnector
	Log       *zerolog.Logger
	DB        *dbutil.Database
	Config    *bridgeconfig.Config
	Matrix    *matrix.Connector
	Bridge    *bridgev2.Bridge

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

func (br *BridgeMain) Run() {
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
	} else if *writeExampleConfig {
		networkExample, _, _ := br.Connector.GetConfig()
		exerrors.PanicIfNotNil(os.WriteFile(*configPath, []byte(br.makeFullExampleConfig(networkExample)), 0600))
		return
	}

	br.loadConfig()
	if *generateRegistration {
		br.GenerateRegistration()
		return
	}

	br.Init()
	err = br.Bridge.Start()
	if err != nil {
		var dbUpgradeErr bridgev2.DBUpgradeError
		if errors.As(err, &dbUpgradeErr) {
			br.LogDBUpgradeErrorAndExit(dbUpgradeErr.Section, dbUpgradeErr.Err)
		} else {
			br.Log.Fatal().Err(err).Msg("Failed to start bridge")
		}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	br.Log.Info().Msg("Shutting down bridge")
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

func (br *BridgeMain) Init() {
	var err error
	br.Log, err = br.Config.Logging.Compile()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to initialize logger:", err)
		os.Exit(12)
	}
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

	exzerolog.SetupDefaults(br.Log)
	br.initDB()
	br.Matrix = matrix.NewConnector(br.Config)
	br.Matrix.IgnoreUnsupportedServer = *ignoreUnsupportedServer
	br.Bridge = bridgev2.NewBridge("", br.DB, *br.Log, &br.Config.Bridge, br.Matrix, br.Connector)
	br.Matrix.AS.DoublePuppetValue = br.Name
	if br.PostInit != nil {
		br.PostInit()
	}
}

func (br *BridgeMain) initDB() {
	br.Log.Debug().Msg("Initializing database connection")
	dbConfig := br.Config.Database
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
	br.DB, err = dbutil.NewFromConfig(br.Name, dbConfig, dbutil.ZeroLogger(br.Log.With().Str("db_section", "main").Logger()))
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
		return errors.New("appservice.database not configured")
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
	networkUpgraderProxied := &configupgrade.ProxyUpgrader{Target: networkUpgrader, Prefix: []string{"network"}}
	upgrader := configupgrade.MergeUpgraders(baseConfig, networkUpgraderProxied, bridgeconfig.Upgrader)
	return upgrader, networkData
}

func (br *BridgeMain) loadConfig() {
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
	err = cfg.Network.Decode(networkData)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to parse network config:", err)
		os.Exit(10)
	}
	br.Config = &cfg
}

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
