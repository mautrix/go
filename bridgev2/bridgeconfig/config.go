// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"
	"slices"
	"time"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/zeroconfig"
	"gopkg.in/yaml.v3"

	"maunium.net/go/mautrix/bridgev2/networkid"
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

	EnvConfigPrefix string `yaml:"env_config_prefix"`

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
	CommandPrefix                 string             `yaml:"command_prefix"`
	PersonalFilteringSpaces       bool               `yaml:"personal_filtering_spaces"`
	PrivateChatPortalMeta         bool               `yaml:"private_chat_portal_meta"`
	AsyncEvents                   bool               `yaml:"async_events"`
	SplitPortals                  bool               `yaml:"split_portals"`
	ResendBridgeInfo              bool               `yaml:"resend_bridge_info"`
	NoBridgeInfoStateKey          bool               `yaml:"no_bridge_info_state_key"`
	BridgeStatusNotices           string             `yaml:"bridge_status_notices"`
	UnknownErrorAutoReconnect     time.Duration      `yaml:"unknown_error_auto_reconnect"`
	UnknownErrorMaxAutoReconnects int                `yaml:"unknown_error_max_auto_reconnects"`
	BridgeMatrixLeave             bool               `yaml:"bridge_matrix_leave"`
	BridgeNotices                 bool               `yaml:"bridge_notices"`
	TagOnlyOnCreate               bool               `yaml:"tag_only_on_create"`
	OnlyBridgeTags                []event.RoomTag    `yaml:"only_bridge_tags"`
	MuteOnlyOnCreate              bool               `yaml:"mute_only_on_create"`
	DeduplicateMatrixMessages     bool               `yaml:"deduplicate_matrix_messages"`
	CrossRoomReplies              bool               `yaml:"cross_room_replies"`
	OutgoingMessageReID           bool               `yaml:"outgoing_message_re_id"`
	RevertFailedStateChanges      bool               `yaml:"revert_failed_state_changes"`
	KickMatrixUsers               bool               `yaml:"kick_matrix_users"`
	EnableSendStateRequests       bool               `yaml:"enable_send_state_requests"`
	CleanupOnLogout               CleanupOnLogouts   `yaml:"cleanup_on_logout"`
	Relay                         RelayConfig        `yaml:"relay"`
	PortalCreateFilter            PortalCreateFilter `yaml:"portal_create_filter"`
	Permissions                   PermissionConfig   `yaml:"permissions"`
	Backfill                      BackfillConfig     `yaml:"backfill"`
}

type MatrixConfig struct {
	MessageStatusEvents   bool  `yaml:"message_status_events"`
	DeliveryReceipts      bool  `yaml:"delivery_receipts"`
	MessageErrorNotices   bool  `yaml:"message_error_notices"`
	SyncDirectChatList    bool  `yaml:"sync_direct_chat_list"`
	FederateRooms         bool  `yaml:"federate_rooms"`
	UploadFileThreshold   int64 `yaml:"upload_file_threshold"`
	GhostExtraProfileInfo bool  `yaml:"ghost_extra_profile_info"`
}

type AnalyticsConfig struct {
	Token  string `yaml:"token"`
	URL    string `yaml:"url"`
	UserID string `yaml:"user_id"`
}

type ProvisioningConfig struct {
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
	Enabled     bool   `yaml:"enabled"`
	SigningKey  string `yaml:"signing_key"`
	Expiry      int    `yaml:"expiry"`
	HashLength  int    `yaml:"hash_length"`
	PathPrefix  string `yaml:"path_prefix"`
	UseDatabase bool   `yaml:"use_database"`
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

type PortalCreateFilterItem struct {
	ID       networkid.PortalID     `yaml:"id"`
	Receiver *networkid.UserLoginID `yaml:"receiver"`
}

func (pcfi *PortalCreateFilterItem) Equals(other *PortalCreateFilterItem) bool {
	if pcfi == nil || other == nil {
		return pcfi == other
	} else if pcfi.ID != other.ID {
		return false
	} else if pcfi.Receiver == nil || other.Receiver == nil {
		return pcfi.Receiver == other.Receiver
	}
	return *pcfi.Receiver == *other.Receiver
}

func (pcfi *PortalCreateFilterItem) Matches(key networkid.PortalKey) bool {
	return pcfi != nil && pcfi.ID == key.ID && (pcfi.Receiver == nil || *pcfi.Receiver == key.Receiver)
}

type umPortalCreateFilterItem PortalCreateFilterItem

func (pcfi *PortalCreateFilterItem) UnmarshalYAML(node *yaml.Node) error {
	err := node.Decode((*umPortalCreateFilterItem)(pcfi))
	if err != nil {
		err2 := node.Decode(&pcfi.ID)
		if err2 != nil {
			return fmt.Errorf("both decode attempts failed: %w / %w", err, err2)
		}
	}
	return nil
}

type PortalCreateFilterMode string

const (
	PortalCreateFilterModeAllow PortalCreateFilterMode = "allow"
	PortalCreateFilterModeDeny  PortalCreateFilterMode = "deny"
)

type PortalCreateFilter struct {
	Mode PortalCreateFilterMode    `yaml:"mode"`
	List []*PortalCreateFilterItem `yaml:"list"`

	AlwaysDenyFromLogin []networkid.UserLoginID `yaml:"always_deny_from_login"`
}

func (pcf *PortalCreateFilter) ShouldAllow(source networkid.UserLoginID, key networkid.PortalKey) bool {
	if slices.Contains(pcf.AlwaysDenyFromLogin, source) {
		return false
	}
	match := slices.ContainsFunc(pcf.List, func(item *PortalCreateFilterItem) bool {
		return item.Matches(key)
	})
	switch pcf.Mode {
	case PortalCreateFilterModeAllow:
		return match
	case PortalCreateFilterModeDeny:
		return !match
	default:
		return true
	}
}
