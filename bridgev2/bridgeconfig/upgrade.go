// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"

	up "go.mau.fi/util/configupgrade"
	"go.mau.fi/util/random"

	"maunium.net/go/mautrix/federation"
)

func doUpgrade(helper up.Helper) {
	if _, isLegacyConfig := helper.Get(up.Str, "appservice", "database", "uri"); isLegacyConfig {
		doMigrateLegacy(helper, false)
		return
	} else if _, isLegacyPython := helper.Get(up.Str, "appservice", "database"); isLegacyPython {
		doMigrateLegacy(helper, true)
		return
	}

	helper.Copy(up.Str, "bridge", "command_prefix")
	helper.Copy(up.Bool, "bridge", "personal_filtering_spaces")
	helper.Copy(up.Bool, "bridge", "private_chat_portal_meta")
	helper.Copy(up.Bool, "bridge", "async_events")
	helper.Copy(up.Bool, "bridge", "split_portals")
	helper.Copy(up.Bool, "bridge", "resend_bridge_info")
	helper.Copy(up.Bool, "bridge", "no_bridge_info_state_key")
	helper.Copy(up.Str|up.Null, "bridge", "bridge_status_notices")
	helper.Copy(up.Bool, "bridge", "bridge_matrix_leave")
	helper.Copy(up.Bool, "bridge", "bridge_notices")
	helper.Copy(up.Bool, "bridge", "tag_only_on_create")
	helper.Copy(up.List, "bridge", "only_bridge_tags")
	helper.Copy(up.Bool, "bridge", "mute_only_on_create")
	helper.Copy(up.Bool, "bridge", "deduplicate_matrix_messages")
	helper.Copy(up.Bool, "bridge", "cross_room_replies")
	helper.Copy(up.Bool, "bridge", "edit_instead_of_delete")
	helper.Copy(up.Bool, "bridge", "cleanup_on_logout", "enabled")
	helper.Copy(up.Str, "bridge", "cleanup_on_logout", "manual", "private")
	helper.Copy(up.Str, "bridge", "cleanup_on_logout", "manual", "relayed")
	helper.Copy(up.Str, "bridge", "cleanup_on_logout", "manual", "shared_no_users")
	helper.Copy(up.Str, "bridge", "cleanup_on_logout", "manual", "shared_has_users")
	helper.Copy(up.Str, "bridge", "cleanup_on_logout", "bad_credentials", "private")
	helper.Copy(up.Str, "bridge", "cleanup_on_logout", "bad_credentials", "relayed")
	helper.Copy(up.Str, "bridge", "cleanup_on_logout", "bad_credentials", "shared_no_users")
	helper.Copy(up.Str, "bridge", "cleanup_on_logout", "bad_credentials", "shared_has_users")
	helper.Copy(up.Bool, "bridge", "relay", "enabled")
	helper.Copy(up.Bool, "bridge", "relay", "admin_only")
	helper.Copy(up.List, "bridge", "relay", "default_relays")
	helper.Copy(up.Map, "bridge", "relay", "message_formats")
	helper.Copy(up.Str, "bridge", "relay", "displayname_format")
	helper.Copy(up.Map, "bridge", "permissions")

	if dbType, ok := helper.Get(up.Str, "database", "type"); ok && dbType == "sqlite3" {
		fmt.Println("Warning: invalid database type sqlite3 in config. Autocorrecting to sqlite3-fk-wal")
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
	helper.Copy(up.Int, "matrix", "upload_file_threshold")

	helper.Copy(up.Str|up.Null, "analytics", "token")
	helper.Copy(up.Str|up.Null, "analytics", "url")
	helper.Copy(up.Str|up.Null, "analytics", "user_id")

	helper.Copy(up.Str, "provisioning", "prefix")
	if secret, ok := helper.Get(up.Str, "provisioning", "shared_secret"); !ok || secret == "generate" {
		sharedSecret := random.String(64)
		helper.Set(up.Str, sharedSecret, "provisioning", "shared_secret")
	} else {
		helper.Copy(up.Str, "provisioning", "shared_secret")
	}
	helper.Copy(up.Bool, "provisioning", "debug_endpoints")
	helper.Copy(up.Bool, "provisioning", "enable_session_transfers")

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

	helper.Copy(up.Bool, "public_media", "enabled")
	if signingKey, ok := helper.Get(up.Str, "public_media", "signing_key"); !ok || signingKey == "generate" {
		helper.Set(up.Str, random.String(64), "public_media", "signing_key")
	} else {
		helper.Copy(up.Str, "public_media", "signing_key")
	}
	helper.Copy(up.Int, "public_media", "expiry")
	helper.Copy(up.Int, "public_media", "hash_length")

	helper.Copy(up.Bool, "backfill", "enabled")
	helper.Copy(up.Int, "backfill", "max_initial_messages")
	helper.Copy(up.Int, "backfill", "max_catchup_messages")
	helper.Copy(up.Int, "backfill", "unread_hours_threshold")
	helper.Copy(up.Int, "backfill", "threads", "max_initial_messages")
	helper.Copy(up.Bool, "backfill", "queue", "enabled")
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
	if val, ok := helper.Get(up.Bool, "appservice", "msc4190"); ok {
		helper.Set(up.Bool, val, "encryption", "msc4190")
	} else {
		helper.Copy(up.Bool, "encryption", "msc4190")
	}
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

var SpacedBlocks = [][]string{
	{"bridge"},
	{"bridge", "bridge_matrix_leave"},
	{"bridge", "cleanup_on_logout"},
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
	{"analytics"},
	{"provisioning"},
	{"public_media"},
	{"direct_media"},
	{"backfill"},
	{"double_puppet"},
	{"encryption"},
	{"logging"},
}

// Upgrader is a config upgrader that copies the default fields in the homeserver, appservice and logging blocks.
var Upgrader up.SpacedUpgrader = &up.StructUpgrader{
	SimpleUpgrader: up.SimpleUpgrader(doUpgrade),
	Blocks:         SpacedBlocks,
}
