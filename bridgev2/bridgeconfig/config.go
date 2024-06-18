// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"go.mau.fi/util/dbutil"
	"go.mau.fi/zeroconfig"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Network      yaml.Node          `yaml:"network"`
	Bridge       BridgeConfig       `yaml:"bridge"`
	Database     dbutil.Config      `yaml:"database"`
	Homeserver   HomeserverConfig   `yaml:"homeserver"`
	AppService   AppserviceConfig   `yaml:"appservice"`
	Matrix       MatrixConfig       `yaml:"matrix"`
	Provisioning ProvisioningConfig `yaml:"provisioning"`
	DirectMedia  DirectMediaConfig  `yaml:"direct_media"`
	DoublePuppet DoublePuppetConfig `yaml:"double_puppet"`
	Encryption   EncryptionConfig   `yaml:"encryption"`
	Logging      zeroconfig.Config  `yaml:"logging"`

	Permissions         PermissionConfig    `yaml:"permissions"`
	ManagementRoomTexts ManagementRoomTexts `yaml:"management_room_texts"`
}

type BridgeConfig struct {
	CommandPrefix string `yaml:"command_prefix"`
}

type MatrixConfig struct {
	MessageStatusEvents bool `yaml:"message_status_events"`
	DeliveryReceipts    bool `yaml:"delivery_receipts"`
	MessageErrorNotices bool `yaml:"message_error_notices"`
	SyncDirectChatList  bool `yaml:"sync_direct_chat_list"`
	FederateRooms       bool `yaml:"federate_rooms"`
}

type ProvisioningConfig struct {
	Prefix         string `yaml:"prefix"`
	SharedSecret   string `yaml:"shared_secret"`
	DebugEndpoints bool   `yaml:"debug_endpoints"`
}

type DirectMediaConfig struct {
	Enabled           bool   `yaml:"enabled"`
	AllowProxy        bool   `yaml:"allow_proxy"`
	ServerName        string `yaml:"server_name"`
	WellKnownResponse string `yaml:"well_known_response"`
	ServerKey         string `yaml:"server_key"`
}

type DoublePuppetConfig struct {
	Servers        map[string]string `yaml:"servers"`
	AllowDiscovery bool              `yaml:"allow_discovery"`
	Secrets        map[string]string `yaml:"secrets"`
}

type ManagementRoomTexts struct {
	Welcome            string `yaml:"welcome"`
	WelcomeConnected   string `yaml:"welcome_connected"`
	WelcomeUnconnected string `yaml:"welcome_unconnected"`
	AdditionalHelp     string `yaml:"additional_help"`
}
