// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"go.mau.fi/util/dbutil"
	"go.mau.fi/zeroconfig"
)

type Config struct {
	Homeserver          HomeserverConfig    `yaml:"homeserver"`
	AppService          AppserviceConfig    `yaml:"appservice"`
	Database            dbutil.Config       `yaml:"database"`
	Bridge              BridgeConfig        `yaml:"bridge"` // TODO this is more like matrix than bridge
	Provisioning        ProvisioningConfig  `yaml:"provisioning"`
	DoublePuppet        DoublePuppetConfig  `yaml:"double_puppet"`
	Encryption          EncryptionConfig    `yaml:"encryption"`
	Permissions         PermissionConfig    `yaml:"permissions"`
	ManagementRoomTexts ManagementRoomTexts `yaml:"management_room_texts"`
	Logging             zeroconfig.Config   `yaml:"logging"`
}

type BridgeConfig struct {
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
