// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	up "go.mau.fi/util/configupgrade"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/random"
	"go.mau.fi/zeroconfig"
	"gopkg.in/yaml.v3"

	"github.com/element-hq/mautrix-go/appservice"
	"github.com/element-hq/mautrix-go/id"
)

type HomeserverSoftware string

const (
	SoftwareStandard HomeserverSoftware = "standard"
	SoftwareAsmux    HomeserverSoftware = "asmux"
	SoftwareHungry   HomeserverSoftware = "hungry"
)

var AllowedHomeserverSoftware = map[HomeserverSoftware]bool{
	SoftwareStandard: true,
	SoftwareAsmux:    true,
	SoftwareHungry:   true,
}

type HomeserverConfig struct {
	Address    string `yaml:"address"`
	Domain     string `yaml:"domain"`
	AsyncMedia bool   `yaml:"async_media"`

	PublicAddress string `yaml:"public_address,omitempty"`

	Software HomeserverSoftware `yaml:"software"`

	StatusEndpoint                string `yaml:"status_endpoint"`
	MessageSendCheckpointEndpoint string `yaml:"message_send_checkpoint_endpoint"`

	Websocket      bool   `yaml:"websocket"`
	WSProxy        string `yaml:"websocket_proxy"`
	WSPingInterval int    `yaml:"ping_interval_seconds"`
}

type AppserviceConfig struct {
	Address  string `yaml:"address"`
	Hostname string `yaml:"hostname"`
	Port     uint16 `yaml:"port"`

	Database dbutil.Config `yaml:"database"`

	ID  string        `yaml:"id"`
	Bot BotUserConfig `yaml:"bot"`

	ASToken string `yaml:"as_token"`
	HSToken string `yaml:"hs_token"`

	EphemeralEvents   bool `yaml:"ephemeral_events"`
	AsyncTransactions bool `yaml:"async_transactions"`
}

func (config *BaseConfig) MakeUserIDRegex(matcher string) *regexp.Regexp {
	usernamePlaceholder := strings.ToLower(random.String(16))
	usernameTemplate := fmt.Sprintf("@%s:%s",
		config.Bridge.FormatUsername(usernamePlaceholder),
		config.Homeserver.Domain)
	usernameTemplate = regexp.QuoteMeta(usernameTemplate)
	usernameTemplate = strings.Replace(usernameTemplate, usernamePlaceholder, matcher, 1)
	usernameTemplate = fmt.Sprintf("^%s$", usernameTemplate)
	return regexp.MustCompile(usernameTemplate)
}

// GenerateRegistration generates a registration file for the homeserver.
func (config *BaseConfig) GenerateRegistration() *appservice.Registration {
	registration := appservice.CreateRegistration()
	config.AppService.HSToken = registration.ServerToken
	config.AppService.ASToken = registration.AppToken
	config.AppService.copyToRegistration(registration)

	registration.SenderLocalpart = random.String(32)
	botRegex := regexp.MustCompile(fmt.Sprintf("^@%s:%s$",
		regexp.QuoteMeta(config.AppService.Bot.Username),
		regexp.QuoteMeta(config.Homeserver.Domain)))
	registration.Namespaces.UserIDs.Register(botRegex, true)
	registration.Namespaces.UserIDs.Register(config.MakeUserIDRegex(".*"), true)

	return registration
}

func (config *BaseConfig) MakeAppService() *appservice.AppService {
	as := appservice.Create()
	as.HomeserverDomain = config.Homeserver.Domain
	_ = as.SetHomeserverURL(config.Homeserver.Address)
	as.Host.Hostname = config.AppService.Hostname
	as.Host.Port = config.AppService.Port
	as.Registration = config.AppService.GetRegistration()
	return as
}

// GetRegistration copies the data from the bridge config into an *appservice.Registration struct.
// This can't be used with the homeserver, see GenerateRegistration for generating files for the homeserver.
func (asc *AppserviceConfig) GetRegistration() *appservice.Registration {
	reg := &appservice.Registration{}
	asc.copyToRegistration(reg)
	reg.SenderLocalpart = asc.Bot.Username
	reg.ServerToken = asc.HSToken
	reg.AppToken = asc.ASToken
	return reg
}

func (asc *AppserviceConfig) copyToRegistration(registration *appservice.Registration) {
	registration.ID = asc.ID
	registration.URL = asc.Address
	falseVal := false
	registration.RateLimited = &falseVal
	registration.EphemeralEvents = asc.EphemeralEvents
	registration.SoruEphemeralEvents = asc.EphemeralEvents
}

type BotUserConfig struct {
	Username    string `yaml:"username"`
	Displayname string `yaml:"displayname"`
	Avatar      string `yaml:"avatar"`

	ParsedAvatar id.ContentURI `yaml:"-"`
}

type serializableBUC BotUserConfig

func (buc *BotUserConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var sbuc serializableBUC
	err := unmarshal(&sbuc)
	if err != nil {
		return err
	}
	*buc = (BotUserConfig)(sbuc)
	if buc.Avatar != "" && buc.Avatar != "remove" {
		buc.ParsedAvatar, err = id.ParseContentURI(buc.Avatar)
		if err != nil {
			return fmt.Errorf("%w in bot avatar", err)
		}
	}
	return nil
}

type BridgeConfig interface {
	FormatUsername(username string) string
	GetEncryptionConfig() EncryptionConfig
	GetCommandPrefix() string
	GetManagementRoomTexts() ManagementRoomTexts
	GetDoublePuppetConfig() DoublePuppetConfig
	GetResendBridgeInfo() bool
	EnableMessageStatusEvents() bool
	EnableMessageErrorNotices() bool
	Validate() error
}

type DoublePuppetConfig struct {
	ServerMap       map[string]string `yaml:"double_puppet_server_map"`
	AllowDiscovery  bool              `yaml:"double_puppet_allow_discovery"`
	SharedSecretMap map[string]string `yaml:"login_shared_secret_map"`
	AllowManual     bool              `yaml:"allow_manual_double_puppeting"`
}

type EncryptionConfig struct {
	Allow      bool `yaml:"allow"`
	Default    bool `yaml:"default"`
	Require    bool `yaml:"require"`
	Appservice bool `yaml:"appservice"`

	PlaintextMentions bool `yaml:"plaintext_mentions"`

	DeleteKeys struct {
		DeleteOutboundOnAck       bool `yaml:"delete_outbound_on_ack"`
		DontStoreOutbound         bool `yaml:"dont_store_outbound"`
		RatchetOnDecrypt          bool `yaml:"ratchet_on_decrypt"`
		DeleteFullyUsedOnDecrypt  bool `yaml:"delete_fully_used_on_decrypt"`
		DeletePrevOnNewSession    bool `yaml:"delete_prev_on_new_session"`
		DeleteOnDeviceDelete      bool `yaml:"delete_on_device_delete"`
		PeriodicallyDeleteExpired bool `yaml:"periodically_delete_expired"`
		DeleteOutdatedInbound     bool `yaml:"delete_outdated_inbound"`
	} `yaml:"delete_keys"`

	VerificationLevels struct {
		Receive id.TrustState `yaml:"receive"`
		Send    id.TrustState `yaml:"send"`
		Share   id.TrustState `yaml:"share"`
	} `yaml:"verification_levels"`
	AllowKeySharing bool `yaml:"allow_key_sharing"`

	Rotation struct {
		EnableCustom bool  `yaml:"enable_custom"`
		Milliseconds int64 `yaml:"milliseconds"`
		Messages     int   `yaml:"messages"`

		DisableDeviceChangeKeyRotation bool `yaml:"disable_device_change_key_rotation"`
	} `yaml:"rotation"`
}

type ManagementRoomTexts struct {
	Welcome            string `yaml:"welcome"`
	WelcomeConnected   string `yaml:"welcome_connected"`
	WelcomeUnconnected string `yaml:"welcome_unconnected"`
	AdditionalHelp     string `yaml:"additional_help"`
}

type BaseConfig struct {
	Homeserver HomeserverConfig  `yaml:"homeserver"`
	AppService AppserviceConfig  `yaml:"appservice"`
	Bridge     BridgeConfig      `yaml:"-"`
	Logging    zeroconfig.Config `yaml:"logging"`
}

func doUpgrade(helper *up.Helper) {
	helper.Copy(up.Str, "homeserver", "address")
	helper.Copy(up.Str, "homeserver", "domain")
	if legacyAsmuxFlag, ok := helper.Get(up.Bool, "homeserver", "asmux"); ok && legacyAsmuxFlag == "true" {
		helper.Set(up.Str, string(SoftwareAsmux), "homeserver", "software")
	} else {
		helper.Copy(up.Str, "homeserver", "software")
	}
	helper.Copy(up.Str|up.Null, "homeserver", "status_endpoint")
	helper.Copy(up.Str|up.Null, "homeserver", "message_send_checkpoint_endpoint")
	helper.Copy(up.Bool, "homeserver", "async_media")
	helper.Copy(up.Str|up.Null, "homeserver", "websocket_proxy")
	helper.Copy(up.Bool, "homeserver", "websocket")
	helper.Copy(up.Int, "homeserver", "ping_interval_seconds")

	helper.Copy(up.Str|up.Null, "appservice", "address")
	helper.Copy(up.Str|up.Null, "appservice", "hostname")
	helper.Copy(up.Int|up.Null, "appservice", "port")
	if dbType, ok := helper.Get(up.Str, "appservice", "database", "type"); ok && dbType == "sqlite3" {
		helper.Set(up.Str, "sqlite3-fk-wal", "appservice", "database", "type")
	} else {
		helper.Copy(up.Str, "appservice", "database", "type")
	}
	helper.Copy(up.Str, "appservice", "database", "uri")
	helper.Copy(up.Int, "appservice", "database", "max_open_conns")
	helper.Copy(up.Int, "appservice", "database", "max_idle_conns")
	helper.Copy(up.Str|up.Null, "appservice", "database", "max_conn_idle_time")
	helper.Copy(up.Str|up.Null, "appservice", "database", "max_conn_lifetime")
	helper.Copy(up.Str, "appservice", "id")
	helper.Copy(up.Str, "appservice", "bot", "username")
	helper.Copy(up.Str, "appservice", "bot", "displayname")
	helper.Copy(up.Str, "appservice", "bot", "avatar")
	helper.Copy(up.Bool, "appservice", "ephemeral_events")
	helper.Copy(up.Bool, "appservice", "async_transactions")
	helper.Copy(up.Str, "appservice", "as_token")
	helper.Copy(up.Str, "appservice", "hs_token")

	if helper.GetNode("logging", "writers") == nil && (helper.GetNode("logging", "print_level") != nil || helper.GetNode("logging", "file_name_format") != nil) {
		_, _ = fmt.Fprintln(os.Stderr, "Migrating legacy log config")
		migrateLegacyLogConfig(helper)
	} else if helper.GetNode("logging", "writers") == nil && (helper.GetNode("logging", "handlers") != nil) {
		_, _ = fmt.Fprintln(os.Stderr, "Migrating Python log config is not currently supported")
		// TODO implement?
		//migratePythonLogConfig(helper)
	} else {
		helper.Copy(up.Map, "logging")
	}
}

type legacyLogConfig struct {
	Directory       string `yaml:"directory"`
	FileNameFormat  string `yaml:"file_name_format"`
	FileDateFormat  string `yaml:"file_date_format"`
	FileMode        uint32 `yaml:"file_mode"`
	TimestampFormat string `yaml:"timestamp_format"`
	RawPrintLevel   string `yaml:"print_level"`
	JSONStdout      bool   `yaml:"print_json"`
	JSONFile        bool   `yaml:"file_json"`
}

func migrateLegacyLogConfig(helper *up.Helper) {
	var llc legacyLogConfig
	var newConfig zeroconfig.Config
	err := helper.GetBaseNode("logging").Decode(&newConfig)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Base config is corrupted: failed to decode example log config:", err)
		return
	} else if len(newConfig.Writers) != 2 || newConfig.Writers[0].Type != "stdout" || newConfig.Writers[1].Type != "file" {
		_, _ = fmt.Fprintln(os.Stderr, "Base log config is not in expected format")
		return
	}
	err = helper.GetNode("logging").Decode(&llc)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to decode legacy log config:", err)
		return
	}
	if llc.RawPrintLevel != "" {
		level, err := zerolog.ParseLevel(llc.RawPrintLevel)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Failed to parse minimum stdout log level:", err)
		} else {
			newConfig.Writers[0].MinLevel = &level
		}
	}
	if llc.Directory != "" && llc.FileNameFormat != "" {
		if llc.FileNameFormat == "{{.Date}}-{{.Index}}.log" {
			llc.FileNameFormat = "bridge.log"
		} else {
			llc.FileNameFormat = strings.ReplaceAll(llc.FileNameFormat, "{{.Date}}", "")
			llc.FileNameFormat = strings.ReplaceAll(llc.FileNameFormat, "{{.Index}}", "")
		}
		newConfig.Writers[1].Filename = filepath.Join(llc.Directory, llc.FileNameFormat)
	} else if llc.FileNameFormat == "" {
		newConfig.Writers = newConfig.Writers[0:1]
	}
	if llc.JSONStdout {
		newConfig.Writers[0].TimeFormat = ""
		newConfig.Writers[0].Format = "json"
	} else if llc.TimestampFormat != "" {
		newConfig.Writers[0].TimeFormat = llc.TimestampFormat
	}
	var updatedConfig yaml.Node
	err = updatedConfig.Encode(&newConfig)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to encode migrated log config:", err)
		return
	}
	*helper.GetBaseNode("logging").Node = updatedConfig
}

// Upgrader is a config upgrader that copies the default fields in the homeserver, appservice and logging blocks.
var Upgrader = up.SimpleUpgrader(doUpgrade)
