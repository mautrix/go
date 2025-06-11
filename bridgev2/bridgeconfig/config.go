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

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/mediaproxy"
)

type Config struct {
	Network      yaml.Node          `yaml:"network"`
	Bridge       BridgeConfig       `yaml:"bridge"`
	Database     dbutil.Config      `yaml:"database"`
	Homeserver   HomeserverConfig   `yaml:"homeserver"`
	AppService   AppserviceConfig   `yaml:"appservice"`
	Matrix       MatrixConfig       `yaml:"matrix"`
	Analytics    AnalyticsConfig    `yaml:"analytics"`
	Provisioning ProvisioningConfig `yaml:"provisioning"`
	PublicMedia  PublicMediaConfig  `yaml:"public_media"`
	DirectMedia  DirectMediaConfig  `yaml:"direct_media"`
	Backfill     BackfillConfig     `yaml:"backfill"`
	DoublePuppet DoublePuppetConfig `yaml:"double_puppet"`
	Encryption   EncryptionConfig   `yaml:"encryption"`
	Logging      zeroconfig.Config  `yaml:"logging"`

	ManagementRoomTexts ManagementRoomTexts `yaml:"management_room_texts"`
}

type CleanupAction string

const (
	CleanupActionNull     CleanupAction = ""
	CleanupActionNothing  CleanupAction = "nothing"
	CleanupActionKick     CleanupAction = "kick"
	CleanupActionUnbridge CleanupAction = "unbridge"
	CleanupActionDelete   CleanupAction = "delete"
)

type CleanupOnLogout struct {
	Private        CleanupAction `yaml:"private"`
	Relayed        CleanupAction `yaml:"relayed"`
	SharedNoUsers  CleanupAction `yaml:"shared_no_users"`
	SharedHasUsers CleanupAction `yaml:"shared_has_users"`
}

type CleanupOnLogouts struct {
	Enabled        bool            `yaml:"enabled"`
	Manual         CleanupOnLogout `yaml:"manual"`
	BadCredentials CleanupOnLogout `yaml:"bad_credentials"`
}

type BridgeConfig struct {
	CommandPrefix             string           `yaml:"command_prefix"`
	PersonalFilteringSpaces   bool             `yaml:"personal_filtering_spaces"`
	PrivateChatPortalMeta     bool             `yaml:"private_chat_portal_meta"`
	AsyncEvents               bool             `yaml:"async_events"`
	SplitPortals              bool             `yaml:"split_portals"`
	ResendBridgeInfo          bool             `yaml:"resend_bridge_info"`
	NoBridgeInfoStateKey      bool             `yaml:"no_bridge_info_state_key"`
	BridgeStatusNotices       string           `yaml:"bridge_status_notices"`
	BridgeMatrixLeave         bool             `yaml:"bridge_matrix_leave"`
	BridgeNotices             bool             `yaml:"bridge_notices"`
	TagOnlyOnCreate           bool             `yaml:"tag_only_on_create"`
	OnlyBridgeTags            []event.RoomTag  `yaml:"only_bridge_tags"`
	MuteOnlyOnCreate          bool             `yaml:"mute_only_on_create"`
	DeduplicateMatrixMessages bool             `yaml:"deduplicate_matrix_messages"`
	CrossRoomReplies          bool             `yaml:"cross_room_replies"`
	EditInsteadOfDelete       bool             `yaml:"edit_instead_of_delete"`
	OutgoingMessageReID       bool             `yaml:"outgoing_message_re_id"`
	CleanupOnLogout           CleanupOnLogouts `yaml:"cleanup_on_logout"`
	Relay                     RelayConfig      `yaml:"relay"`
	Permissions               PermissionConfig `yaml:"permissions"`
	Backfill                  BackfillConfig   `yaml:"backfill"`
}

type MatrixConfig struct {
	MessageStatusEvents bool  `yaml:"message_status_events"`
	DeliveryReceipts    bool  `yaml:"delivery_receipts"`
	MessageErrorNotices bool  `yaml:"message_error_notices"`
	SyncDirectChatList  bool  `yaml:"sync_direct_chat_list"`
	FederateRooms       bool  `yaml:"federate_rooms"`
	UploadFileThreshold int64 `yaml:"upload_file_threshold"`
}

type AnalyticsConfig struct {
	Token  string `yaml:"token"`
	URL    string `yaml:"url"`
	UserID string `yaml:"user_id"`
}

type ProvisioningConfig struct {
	Prefix                 string `yaml:"prefix"`
	SharedSecret           string `yaml:"shared_secret"`
	DebugEndpoints         bool   `yaml:"debug_endpoints"`
	EnableSessionTransfers bool   `yaml:"enable_session_transfers"`
}

type DirectMediaConfig struct {
	Enabled                bool   `yaml:"enabled"`
	MediaIDPrefix          string `yaml:"media_id_prefix"`
	mediaproxy.BasicConfig `yaml:",inline"`
}

type PublicMediaConfig struct {
	Enabled    bool   `yaml:"enabled"`
	SigningKey string `yaml:"signing_key"`
	HashLength int    `yaml:"hash_length"`
	Expiry     int    `yaml:"expiry"`
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
