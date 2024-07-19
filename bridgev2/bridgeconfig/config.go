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

	"maunium.net/go/mautrix/mediaproxy"
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
	Backfill     BackfillConfig     `yaml:"backfill"`
	DoublePuppet DoublePuppetConfig `yaml:"double_puppet"`
	Encryption   EncryptionConfig   `yaml:"encryption"`
	Logging      zeroconfig.Config  `yaml:"logging"`

	ManagementRoomTexts ManagementRoomTexts `yaml:"management_room_texts"`
}

type BridgeConfig struct {
	CommandPrefix           string           `yaml:"command_prefix"`
	PersonalFilteringSpaces bool             `yaml:"personal_filtering_spaces"`
	PrivateChatPortalMeta   bool             `yaml:"private_chat_portal_meta"`
	Relay                   RelayConfig      `yaml:"relay"`
	Permissions             PermissionConfig `yaml:"permissions"`
	Backfill                BackfillConfig   `yaml:"backfill"`
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
	Enabled                bool   `yaml:"enabled"`
	MediaIDPrefix          string `yaml:"media_id_prefix"`
	mediaproxy.BasicConfig `yaml:",inline"`
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
