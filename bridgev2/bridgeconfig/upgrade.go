// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"
	"os"

	up "go.mau.fi/util/configupgrade"
	"go.mau.fi/util/random"

	"maunium.net/go/mautrix/federation"
)

func doUpgrade(helper up.Helper) {
	if _, isLegacyConfig := helper.Get(up.Str, "appservice", "database", "uri"); isLegacyConfig {
		doMigrateLegacy(helper)
		return
	}

	helper.Copy(up.Str, "bridge", "command_prefix")
	helper.Copy(up.Bool, "bridge", "personal_filtering_spaces")
	helper.Copy(up.Bool, "bridge", "relay", "enabled")
	helper.Copy(up.Bool, "bridge", "relay", "admin_only")
	helper.Copy(up.List, "bridge", "relay", "default_relays")
	helper.Copy(up.Map, "bridge", "relay", "message_formats")
	helper.Copy(up.Map, "bridge", "permissions")

	if dbType, ok := helper.Get(up.Str, "database", "type"); ok && dbType == "sqlite3" {
		helper.Set(up.Str, "sqlite3-fk-wal", "database", "type")
	} else {
		helper.Copy(up.Str, "database", "type")
	}
	helper.Copy(up.Str, "database", "uri")
	helper.Copy(up.Int, "database", "max_open_conns")
	helper.Copy(up.Int, "database", "max_idle_conns")
	helper.Copy(up.Str|up.Null, "database", "max_conn_idle_time")
	helper.Copy(up.Str|up.Null, "database", "max_conn_lifetime")

	helper.Copy(up.Str, "homeserver", "address")
	helper.Copy(up.Str, "homeserver", "domain")
	helper.Copy(up.Str, "homeserver", "software")
	helper.Copy(up.Str|up.Null, "homeserver", "status_endpoint")
	helper.Copy(up.Str|up.Null, "homeserver", "message_send_checkpoint_endpoint")
	helper.Copy(up.Bool, "homeserver", "async_media")
	helper.Copy(up.Str|up.Null, "homeserver", "websocket_proxy")
	helper.Copy(up.Bool, "homeserver", "websocket")
	helper.Copy(up.Int, "homeserver", "ping_interval_seconds")

	helper.Copy(up.Str|up.Null, "appservice", "address")
	helper.Copy(up.Str|up.Null, "appservice", "public_address")
	helper.Copy(up.Str|up.Null, "appservice", "hostname")
	helper.Copy(up.Int|up.Null, "appservice", "port")
	helper.Copy(up.Str, "appservice", "id")
	helper.Copy(up.Str, "appservice", "bot", "username")
	helper.Copy(up.Str, "appservice", "bot", "displayname")
	helper.Copy(up.Str, "appservice", "bot", "avatar")
	helper.Copy(up.Bool, "appservice", "ephemeral_events")
	helper.Copy(up.Bool, "appservice", "async_transactions")
	helper.Copy(up.Str, "appservice", "as_token")
	helper.Copy(up.Str, "appservice", "hs_token")
	helper.Copy(up.Str, "appservice", "username_template")

	helper.Copy(up.Bool, "matrix", "message_status_events")
	helper.Copy(up.Bool, "matrix", "delivery_receipts")
	helper.Copy(up.Bool, "matrix", "message_error_notices")
	helper.Copy(up.Bool, "matrix", "sync_direct_chat_list")
	helper.Copy(up.Bool, "matrix", "federate_rooms")

	helper.Copy(up.Str, "provisioning", "prefix")
	if secret, ok := helper.Get(up.Str, "provisioning", "shared_secret"); !ok || secret == "generate" {
		sharedSecret := random.String(64)
		helper.Set(up.Str, sharedSecret, "provisioning", "shared_secret")
	} else {
		helper.Copy(up.Str, "provisioning", "shared_secret")
	}
	helper.Copy(up.Bool, "provisioning", "debug_endpoints")

	helper.Copy(up.Bool, "direct_media", "enabled")
	helper.Copy(up.Str|up.Null, "direct_media", "media_id_prefix")
	helper.Copy(up.Str, "direct_media", "server_name")
	helper.Copy(up.Str|up.Null, "direct_media", "well_known_response")
	helper.Copy(up.Bool, "direct_media", "allow_proxy")
	if serverKey, ok := helper.Get(up.Str, "direct_media", "server_key"); !ok || serverKey == "generate" {
		serverKey = federation.GenerateSigningKey().SynapseString()
		helper.Set(up.Str, serverKey, "direct_media", "server_key")
	} else {
		helper.Copy(up.Str, "direct_media", "server_key")
	}

	helper.Copy(up.Bool, "backfill", "enabled")
	helper.Copy(up.Int, "backfill", "max_initial_messages")
	helper.Copy(up.Int, "backfill", "max_catchup_messages")
	helper.Copy(up.Int, "backfill", "unread_hours_threshold")
	helper.Copy(up.Bool, "backfill", "threads", "max_initial_messages")
	helper.Copy(up.Int, "backfill", "queue", "enabled")
	helper.Copy(up.Int, "backfill", "queue", "batch_size")
	helper.Copy(up.Int, "backfill", "queue", "batch_delay")
	helper.Copy(up.Int, "backfill", "queue", "max_batches")
	helper.Copy(up.Map, "backfill", "queue", "max_batches_override")

	helper.Copy(up.Map, "double_puppet", "servers")
	helper.Copy(up.Bool, "double_puppet", "allow_discovery")
	helper.Copy(up.Map, "double_puppet", "secrets")

	helper.Copy(up.Bool, "encryption", "allow")
	helper.Copy(up.Bool, "encryption", "default")
	helper.Copy(up.Bool, "encryption", "require")
	helper.Copy(up.Bool, "encryption", "appservice")
	helper.Copy(up.Bool, "encryption", "allow_key_sharing")
	if secret, ok := helper.Get(up.Str, "encryption", "pickle_key"); !ok || secret == "generate" {
		helper.Set(up.Str, random.String(64), "encryption", "pickle_key")
	} else {
		helper.Copy(up.Str, "encryption", "pickle_key")
	}
	helper.Copy(up.Bool, "encryption", "delete_keys", "delete_outbound_on_ack")
	helper.Copy(up.Bool, "encryption", "delete_keys", "dont_store_outbound")
	helper.Copy(up.Bool, "encryption", "delete_keys", "ratchet_on_decrypt")
	helper.Copy(up.Bool, "encryption", "delete_keys", "delete_fully_used_on_decrypt")
	helper.Copy(up.Bool, "encryption", "delete_keys", "delete_prev_on_new_session")
	helper.Copy(up.Bool, "encryption", "delete_keys", "delete_on_device_delete")
	helper.Copy(up.Bool, "encryption", "delete_keys", "periodically_delete_expired")
	helper.Copy(up.Bool, "encryption", "delete_keys", "delete_outdated_inbound")
	helper.Copy(up.Str, "encryption", "verification_levels", "receive")
	helper.Copy(up.Str, "encryption", "verification_levels", "send")
	helper.Copy(up.Str, "encryption", "verification_levels", "share")
	helper.Copy(up.Bool, "encryption", "rotation", "enable_custom")
	helper.Copy(up.Int, "encryption", "rotation", "milliseconds")
	helper.Copy(up.Int, "encryption", "rotation", "messages")
	helper.Copy(up.Bool, "encryption", "rotation", "disable_device_change_key_rotation")

	helper.Copy(up.Map, "logging")
}

func CopyToOtherLocation(helper up.Helper, fieldType up.YAMLType, source, dest []string) {
	val, ok := helper.Get(fieldType, source...)
	if ok {
		helper.Set(fieldType, val, dest...)
	}
}

func CopyMapToOtherLocation(helper up.Helper, source, dest []string) {
	val := helper.GetNode(source...)
	if val != nil && val.Map != nil {
		helper.SetMap(val.Map, dest...)
	}
}

var HackyMigrateLegacyNetworkConfig func(up.Helper)

func doMigrateLegacy(helper up.Helper) {
	if HackyMigrateLegacyNetworkConfig == nil {
		_, _ = fmt.Fprintln(os.Stderr, "Legacy bridge config detected, but hacky network config migrator is not set")
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stderr, "Migrating legacy bridge config")

	helper.Copy(up.Str, "homeserver", "address")
	helper.Copy(up.Str, "homeserver", "domain")
	helper.Copy(up.Str, "homeserver", "software")
	helper.Copy(up.Str|up.Null, "homeserver", "status_endpoint")
	helper.Copy(up.Str|up.Null, "homeserver", "message_send_checkpoint_endpoint")
	helper.Copy(up.Bool, "homeserver", "async_media")
	helper.Copy(up.Str|up.Null, "homeserver", "websocket_proxy")
	helper.Copy(up.Bool, "homeserver", "websocket")
	helper.Copy(up.Int, "homeserver", "ping_interval_seconds")

	helper.Copy(up.Str|up.Null, "appservice", "address")
	helper.Copy(up.Str|up.Null, "appservice", "hostname")
	helper.Copy(up.Int|up.Null, "appservice", "port")
	helper.Copy(up.Str, "appservice", "id")
	helper.Copy(up.Str, "appservice", "bot", "username")
	helper.Copy(up.Str, "appservice", "bot", "displayname")
	helper.Copy(up.Str, "appservice", "bot", "avatar")
	helper.Copy(up.Bool, "appservice", "ephemeral_events")
	helper.Copy(up.Bool, "appservice", "async_transactions")
	helper.Copy(up.Str, "appservice", "as_token")
	helper.Copy(up.Str, "appservice", "hs_token")

	helper.Copy(up.Str, "bridge", "command_prefix")
	helper.Copy(up.Bool, "bridge", "personal_filtering_spaces")
	helper.Copy(up.Bool, "bridge", "relay", "enabled")
	helper.Copy(up.Bool, "bridge", "relay", "admin_only")
	helper.Copy(up.Map, "bridge", "permissions")

	CopyToOtherLocation(helper, up.Str, []string{"appservice", "database", "type"}, []string{"database", "type"})
	CopyToOtherLocation(helper, up.Str, []string{"appservice", "database", "uri"}, []string{"database", "uri"})
	CopyToOtherLocation(helper, up.Int, []string{"appservice", "database", "max_open_conns"}, []string{"database", "max_open_conns"})
	CopyToOtherLocation(helper, up.Int, []string{"appservice", "database", "max_idle_conns"}, []string{"database", "max_idle_conns"})
	CopyToOtherLocation(helper, up.Int, []string{"appservice", "database", "max_conn_idle_time"}, []string{"database", "max_conn_idle_time"})
	CopyToOtherLocation(helper, up.Int, []string{"appservice", "database", "max_conn_lifetime"}, []string{"database", "max_conn_lifetime"})

	CopyToOtherLocation(helper, up.Str, []string{"bridge", "username_template"}, []string{"appservice", "username_template"})

	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "message_status_events"}, []string{"matrix", "message_status_events"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "delivery_receipts"}, []string{"matrix", "delivery_receipts"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "message_error_notices"}, []string{"matrix", "message_error_notices"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "sync_direct_chat_list"}, []string{"matrix", "sync_direct_chat_list"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "federate_rooms"}, []string{"matrix", "federate_rooms"})

	CopyToOtherLocation(helper, up.Str, []string{"bridge", "provisioning", "prefix"}, []string{"provisioning", "prefix"})
	CopyToOtherLocation(helper, up.Str, []string{"bridge", "provisioning", "shared_secret"}, []string{"provisioning", "shared_secret"})
	CopyToOtherLocation(helper, up.Str, []string{"appservice", "provisioning", "prefix"}, []string{"provisioning", "prefix"})
	CopyToOtherLocation(helper, up.Str, []string{"appservice", "provisioning", "shared_secret"}, []string{"provisioning", "shared_secret"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "provisioning", "debug_endpoints"}, []string{"provisioning", "debug_endpoints"})

	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "double_puppet_allow_discovery"}, []string{"double_puppet", "allow_discovery"})
	CopyMapToOtherLocation(helper, []string{"bridge", "double_puppet_server_map"}, []string{"double_puppet", "servers"})
	CopyMapToOtherLocation(helper, []string{"bridge", "login_shared_secret_map"}, []string{"double_puppet", "secrets"})

	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "allow"}, []string{"encryption", "allow"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "default"}, []string{"encryption", "default"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "require"}, []string{"encryption", "require"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "appservice"}, []string{"encryption", "appservice"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "allow_key_sharing"}, []string{"encryption", "allow_key_sharing"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "delete_keys", "delete_outbound_on_ack"}, []string{"encryption", "delete_keys", "delete_outbound_on_ack"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "delete_keys", "dont_store_outbound"}, []string{"encryption", "delete_keys", "dont_store_outbound"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "delete_keys", "ratchet_on_decrypt"}, []string{"encryption", "delete_keys", "ratchet_on_decrypt"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "delete_keys", "delete_fully_used_on_decrypt"}, []string{"encryption", "delete_keys", "delete_fully_used_on_decrypt"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "delete_keys", "delete_prev_on_new_session"}, []string{"encryption", "delete_keys", "delete_prev_on_new_session"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "delete_keys", "delete_on_device_delete"}, []string{"encryption", "delete_keys", "delete_on_device_delete"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "delete_keys", "periodically_delete_expired"}, []string{"encryption", "delete_keys", "periodically_delete_expired"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "delete_keys", "delete_outdated_inbound"}, []string{"encryption", "delete_keys", "delete_outdated_inbound"})
	CopyToOtherLocation(helper, up.Str, []string{"bridge", "encryption", "verification_levels", "receive"}, []string{"encryption", "verification_levels", "receive"})
	CopyToOtherLocation(helper, up.Str, []string{"bridge", "encryption", "verification_levels", "send"}, []string{"encryption", "verification_levels", "send"})
	CopyToOtherLocation(helper, up.Str, []string{"bridge", "encryption", "verification_levels", "share"}, []string{"encryption", "verification_levels", "share"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "rotation", "enable_custom"}, []string{"encryption", "rotation", "enable_custom"})
	CopyToOtherLocation(helper, up.Int, []string{"bridge", "encryption", "rotation", "milliseconds"}, []string{"encryption", "rotation", "milliseconds"})
	CopyToOtherLocation(helper, up.Int, []string{"bridge", "encryption", "rotation", "messages"}, []string{"encryption", "rotation", "messages"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "encryption", "rotation", "disable_device_change_key_rotation"}, []string{"encryption", "rotation", "disable_device_change_key_rotation"})

	if helper.GetNode("logging", "writers") == nil && (helper.GetNode("logging", "print_level") != nil || helper.GetNode("logging", "file_name_format") != nil) {
		_, _ = fmt.Fprintln(os.Stderr, "Migrating maulogger configs is not supported")
	} else if helper.GetNode("logging", "writers") == nil && (helper.GetNode("logging", "handlers") != nil) {
		_, _ = fmt.Fprintln(os.Stderr, "Migrating Python log configs is not supported")
	} else {
		helper.Copy(up.Map, "logging")
	}

	HackyMigrateLegacyNetworkConfig(helper)
}

var SpacedBlocks = [][]string{
	{"bridge"},
	{"bridge", "relay"},
	{"bridge", "permissions"},
	{"database"},
	{"homeserver"},
	{"homeserver", "software"},
	{"homeserver", "websocket"},
	{"appservice"},
	{"appservice", "hostname"},
	{"appservice", "id"},
	{"appservice", "ephemeral_events"},
	{"appservice", "as_token"},
	{"appservice", "username_template"},
	{"matrix"},
	{"provisioning"},
	{"backfill"},
	{"direct_media"},
	{"double_puppet"},
	{"encryption"},
	{"logging"},
}

// Upgrader is a config upgrader that copies the default fields in the homeserver, appservice and logging blocks.
var Upgrader up.SpacedUpgrader = &up.StructUpgrader{
	SimpleUpgrader: up.SimpleUpgrader(doUpgrade),
	Blocks:         SpacedBlocks,
}
