// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	up "go.mau.fi/util/configupgrade"
)

var HackyMigrateLegacyNetworkConfig func(up.Helper)

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

func doMigrateLegacy(helper up.Helper, python bool) {
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
	if python {
		CopyToOtherLocation(helper, up.Str, []string{"appservice", "bot_username"}, []string{"appservice", "bot", "username"})
		CopyToOtherLocation(helper, up.Str, []string{"appservice", "bot_displayname"}, []string{"appservice", "bot", "displayname"})
		CopyToOtherLocation(helper, up.Str, []string{"appservice", "bot_avatar"}, []string{"appservice", "bot", "avatar"})
	} else {
		helper.Copy(up.Str, "appservice", "bot", "username")
		helper.Copy(up.Str, "appservice", "bot", "displayname")
		helper.Copy(up.Str, "appservice", "bot", "avatar")
	}
	helper.Copy(up.Bool, "appservice", "ephemeral_events")
	helper.Copy(up.Bool, "appservice", "async_transactions")
	helper.Copy(up.Str, "appservice", "as_token")
	helper.Copy(up.Str, "appservice", "hs_token")

	helper.Copy(up.Str, "bridge", "command_prefix")
	helper.Copy(up.Bool, "bridge", "personal_filtering_spaces")
	if oldPM, ok := helper.Get(up.Str, "bridge", "private_chat_portal_meta"); ok && (oldPM == "default" || oldPM == "always") {
		helper.Set(up.Bool, "true", "bridge", "private_chat_portal_meta")
	} else {
		helper.Set(up.Bool, "false", "bridge", "private_chat_portal_meta")
	}
	helper.Copy(up.Bool, "bridge", "relay", "enabled")
	helper.Copy(up.Bool, "bridge", "relay", "admin_only")
	helper.Copy(up.Map, "bridge", "permissions")

	if python {
		legacyDB, ok := helper.Get(up.Str, "appservice", "database")
		if ok {
			if strings.HasPrefix(legacyDB, "postgres") {
				parsedDB, err := url.Parse(legacyDB)
				if err != nil {
					panic(err)
				}
				q := parsedDB.Query()
				if parsedDB.Host == "" && !q.Has("host") {
					q.Set("host", "/var/run/postgresql")
				} else if !q.Has("sslmode") {
					q.Set("sslmode", "disable")
				}
				parsedDB.RawQuery = q.Encode()
				helper.Set(up.Str, parsedDB.String(), "database", "uri")
				helper.Set(up.Str, "postgres", "database", "type")
			} else {
				dbPath := strings.TrimPrefix(strings.TrimPrefix(legacyDB, "sqlite:"), "///")
				helper.Set(up.Str, fmt.Sprintf("file:%s?_txlock=immediate", dbPath), "database", "uri")
				helper.Set(up.Str, "sqlite3-fk-wal", "database", "type")
			}
		}
		if legacyDBMinSize, ok := helper.Get(up.Int, "appservice", "database_opts", "min_size"); ok {
			helper.Set(up.Int, legacyDBMinSize, "database", "max_idle_conns")
		}
		if legacyDBMaxSize, ok := helper.Get(up.Int, "appservice", "database_opts", "max_size"); ok {
			helper.Set(up.Int, legacyDBMaxSize, "database", "max_open_conns")
		}
	} else {
		if dbType, ok := helper.Get(up.Str, "appservice", "database", "type"); ok && dbType == "sqlite3" {
			helper.Set(up.Str, "sqlite3-fk-wal", "database", "type")
		} else {
			CopyToOtherLocation(helper, up.Str, []string{"appservice", "database", "type"}, []string{"database", "type"})
		}
		CopyToOtherLocation(helper, up.Str, []string{"appservice", "database", "uri"}, []string{"database", "uri"})
		CopyToOtherLocation(helper, up.Int, []string{"appservice", "database", "max_open_conns"}, []string{"database", "max_open_conns"})
		CopyToOtherLocation(helper, up.Int, []string{"appservice", "database", "max_idle_conns"}, []string{"database", "max_idle_conns"})
		CopyToOtherLocation(helper, up.Int, []string{"appservice", "database", "max_conn_idle_time"}, []string{"database", "max_conn_idle_time"})
		CopyToOtherLocation(helper, up.Int, []string{"appservice", "database", "max_conn_lifetime"}, []string{"database", "max_conn_lifetime"})
	}

	if python {
		if usernameTemplate, ok := helper.Get(up.Str, "bridge", "username_template"); ok && strings.Contains(usernameTemplate, "{userid}") {
			helper.Set(up.Str, strings.ReplaceAll(usernameTemplate, "{userid}", "{{.}}"), "appservice", "username_template")
		}
	} else {
		CopyToOtherLocation(helper, up.Str, []string{"bridge", "username_template"}, []string{"appservice", "username_template"})
	}

	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "message_status_events"}, []string{"matrix", "message_status_events"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "delivery_receipts"}, []string{"matrix", "delivery_receipts"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "message_error_notices"}, []string{"matrix", "message_error_notices"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "sync_direct_chat_list"}, []string{"matrix", "sync_direct_chat_list"})
	CopyToOtherLocation(helper, up.Bool, []string{"bridge", "federate_rooms"}, []string{"matrix", "federate_rooms"})

	CopyToOtherLocation(helper, up.Str, []string{"bridge", "provisioning", "shared_secret"}, []string{"provisioning", "shared_secret"})
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
	} else if (helper.GetNode("logging", "writers") == nil && (helper.GetNode("logging", "handlers") != nil)) || python {
		_, _ = fmt.Fprintln(os.Stderr, "Migrating Python log configs is not supported")
	} else {
		helper.Copy(up.Map, "logging")
	}

	HackyMigrateLegacyNetworkConfig(helper)
}
