// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/random"
	"gopkg.in/yaml.v3"

	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/id"
)

type AppserviceConfig struct {
	Address       string `yaml:"address"`
	PublicAddress string `yaml:"public_address"`
	Hostname      string `yaml:"hostname"`
	Port          uint16 `yaml:"port"`

	ID  string        `yaml:"id"`
	Bot BotUserConfig `yaml:"bot"`

	ASToken string `yaml:"as_token"`
	HSToken string `yaml:"hs_token"`

	EphemeralEvents   bool `yaml:"ephemeral_events"`
	AsyncTransactions bool `yaml:"async_transactions"`

	UsernameTemplate string             `yaml:"username_template"`
	usernameTemplate *template.Template `yaml:"-"`
}

func (asc *AppserviceConfig) FormatUsername(username string) string {
	if asc.usernameTemplate == nil {
		asc.usernameTemplate = exerrors.Must(template.New("username").Parse(asc.UsernameTemplate))
	}
	var buf strings.Builder
	_ = asc.usernameTemplate.Execute(&buf, username)
	return buf.String()
}

func (config *Config) MakeUserIDRegex(matcher string) *regexp.Regexp {
	usernamePlaceholder := strings.ToLower(random.String(16))
	usernameTemplate := fmt.Sprintf("@%s:%s",
		config.AppService.FormatUsername(usernamePlaceholder),
		config.Homeserver.Domain)
	usernameTemplate = regexp.QuoteMeta(usernameTemplate)
	usernameTemplate = strings.Replace(usernameTemplate, usernamePlaceholder, matcher, 1)
	usernameTemplate = fmt.Sprintf("^%s$", usernameTemplate)
	return regexp.MustCompile(usernameTemplate)
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

func (ec *EncryptionConfig) applyUnstableFlags(registration *appservice.Registration) {
	registration.MSC4190 = ec.MSC4190
	registration.MSC3202 = ec.Appservice
}

// GenerateRegistration generates a registration file for the homeserver.
func (config *Config) GenerateRegistration() *appservice.Registration {
	registration := appservice.CreateRegistration()
	config.AppService.HSToken = registration.ServerToken
	config.AppService.ASToken = registration.AppToken
	config.AppService.copyToRegistration(registration)
	config.Encryption.applyUnstableFlags(registration)

	registration.SenderLocalpart = random.String(32)
	botRegex := regexp.MustCompile(fmt.Sprintf("^@%s:%s$",
		regexp.QuoteMeta(config.AppService.Bot.Username),
		regexp.QuoteMeta(config.Homeserver.Domain)))
	registration.Namespaces.UserIDs.Register(botRegex, true)
	registration.Namespaces.UserIDs.Register(config.MakeUserIDRegex(".*"), true)

	return registration
}

func (config *Config) MakeAppService() *appservice.AppService {
	as := appservice.Create()
	as.HomeserverDomain = config.Homeserver.Domain
	_ = as.SetHomeserverURL(config.Homeserver.Address)
	as.Host.Hostname = config.AppService.Hostname
	as.Host.Port = config.AppService.Port
	as.Registration = config.AppService.GetRegistration()
	config.Encryption.applyUnstableFlags(as.Registration)
	return as
}

type BotUserConfig struct {
	Username    string `yaml:"username"`
	Displayname string `yaml:"displayname"`
	Avatar      string `yaml:"avatar"`

	ParsedAvatar id.ContentURI `yaml:"-"`
}

type serializableBUC BotUserConfig

func (buc *BotUserConfig) UnmarshalYAML(node *yaml.Node) error {
	var sbuc serializableBUC
	err := node.Decode(&sbuc)
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
