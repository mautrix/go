// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"
	"regexp"
	"strings"

	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/util"
	up "maunium.net/go/mautrix/util/configupgrade"
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

	Software HomeserverSoftware `yaml:"software"`

	StatusEndpoint                string `yaml:"status_endpoint"`
	MessageSendCheckpointEndpoint string `yaml:"message_send_checkpoint_endpoint"`

	WSProxy        string `yaml:"websocket_proxy"`
	WSPingInterval int    `yaml:"ping_interval_seconds"`
}

type AppserviceConfig struct {
	Address  string `yaml:"address"`
	Hostname string `yaml:"hostname"`
	Port     uint16 `yaml:"port"`

	Database DatabaseConfig `yaml:"database"`

	ID  string        `yaml:"id"`
	Bot BotUserConfig `yaml:"bot"`

	ASToken string `yaml:"as_token"`
	HSToken string `yaml:"hs_token"`

	EphemeralEvents bool `yaml:"ephemeral_events"`
}

func (config *BaseConfig) MakeUserIDRegex() *regexp.Regexp {
	usernamePlaceholder := util.RandomString(16)
	usernameTemplate := fmt.Sprintf("@%s:%s",
		config.Bridge.FormatUsername(usernamePlaceholder),
		config.Homeserver.Domain)
	usernameTemplate = regexp.QuoteMeta(usernameTemplate)
	usernameTemplate = strings.Replace(usernameTemplate, usernamePlaceholder, ".+", 1)
	usernameTemplate = fmt.Sprintf("^%s$", usernameTemplate)
	return regexp.MustCompile(usernameTemplate)
}

// GenerateRegistration generates a registration file for the homeserver.
func (config *BaseConfig) GenerateRegistration() *appservice.Registration {
	registration := appservice.CreateRegistration()
	config.AppService.HSToken = registration.ServerToken
	config.AppService.ASToken = registration.AppToken
	config.AppService.copyToRegistration(registration)

	registration.SenderLocalpart = util.RandomString(32)
	botRegex := regexp.MustCompile(fmt.Sprintf("^@%s:%s$",
		regexp.QuoteMeta(config.AppService.Bot.Username),
		regexp.QuoteMeta(config.Homeserver.Domain)))
	registration.Namespaces.UserIDs.Register(botRegex, true)
	registration.Namespaces.UserIDs.Register(config.MakeUserIDRegex(), true)

	return registration
}

func (config *BaseConfig) MakeAppService() *appservice.AppService {
	as := appservice.Create()
	as.HomeserverDomain = config.Homeserver.Domain
	as.HomeserverURL = config.Homeserver.Address
	as.Host.Hostname = config.AppService.Hostname
	as.Host.Port = config.AppService.Port
	as.DefaultHTTPRetries = 4
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

type DatabaseConfig struct {
	Type string `yaml:"type"`
	URI  string `yaml:"uri"`

	MaxOpenConns int `yaml:"max_open_conns"`
	MaxIdleConns int `yaml:"max_idle_conns"`

	ConnMaxIdleTime string `yaml:"conn_max_idle_time"`
	ConnMaxLifetime string `yaml:"conn_max_lifetime"`
}

type BridgeConfig interface {
	FormatUsername(username string) string
	GetEncryptionConfig() EncryptionConfig
	GetCommandPrefix() string
	GetManagementRoomTexts() ManagementRoomTexts
	GetResendBridgeInfo() bool
	EnableMessageStatusEvents() bool
	EnableMessageErrorNotices() bool
	Validate() error
}

type EncryptionConfig struct {
	Allow      bool `yaml:"allow"`
	Default    bool `yaml:"default"`
	Require    bool `yaml:"require"`
	Appservice bool `yaml:"appservice"`

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
	} `yaml:"rotation"`
}

type ManagementRoomTexts struct {
	Welcome            string `yaml:"welcome"`
	WelcomeConnected   string `yaml:"welcome_connected"`
	WelcomeUnconnected string `yaml:"welcome_unconnected"`
	AdditionalHelp     string `yaml:"additional_help"`
}

type BaseConfig struct {
	Homeserver HomeserverConfig     `yaml:"homeserver"`
	AppService AppserviceConfig     `yaml:"appservice"`
	Bridge     BridgeConfig         `yaml:"-"`
	Logging    appservice.LogConfig `yaml:"logging"`
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
	helper.Copy(up.Int, "homeserver", "ping_interval_seconds")

	helper.Copy(up.Str, "appservice", "address")
	helper.Copy(up.Str, "appservice", "hostname")
	helper.Copy(up.Int, "appservice", "port")
	helper.Copy(up.Str, "appservice", "database", "type")
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
	helper.Copy(up.Str, "appservice", "as_token")
	helper.Copy(up.Str, "appservice", "hs_token")

	helper.Copy(up.Str, "logging", "directory")
	helper.Copy(up.Str|up.Null, "logging", "file_name_format")
	helper.Copy(up.Str|up.Timestamp, "logging", "file_date_format")
	helper.Copy(up.Int, "logging", "file_mode")
	helper.Copy(up.Str|up.Timestamp, "logging", "timestamp_format")
	helper.Copy(up.Str, "logging", "print_level")
	helper.Copy(up.Bool, "logging", "print_json")
	helper.Copy(up.Bool, "logging", "file_json")
}

// Upgrader is a config upgrader that copies the default fields in the homeserver, appservice and logging blocks.
var Upgrader = up.SimpleUpgrader(doUpgrade)
