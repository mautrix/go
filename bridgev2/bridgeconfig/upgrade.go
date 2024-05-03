// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	up "go.mau.fi/util/configupgrade"
	"go.mau.fi/zeroconfig"
	"gopkg.in/yaml.v3"
)

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
	helper.Copy(up.Bool, "homeserver", "websocket")
	helper.Copy(up.Int, "homeserver", "ping_interval_seconds")

	helper.Copy(up.Str|up.Null, "appservice", "address")
	helper.Copy(up.Str|up.Null, "appservice", "hostname")
	helper.Copy(up.Int|up.Null, "appservice", "port")
	if dbType, ok := helper.Get(up.Str, "appservice", "database", "type"); ok && dbType == "sqlite3" {
		helper.Set(up.Str, "sqlite3-fk-wal", "appservice", "database", "type")
	} else {
		helper.Copy(up.Str, "appservice", "database", "type")
	}
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
	helper.Copy(up.Bool, "appservice", "async_transactions")
	helper.Copy(up.Str, "appservice", "as_token")
	helper.Copy(up.Str, "appservice", "hs_token")

	if helper.GetNode("logging", "writers") == nil && (helper.GetNode("logging", "print_level") != nil || helper.GetNode("logging", "file_name_format") != nil) {
		_, _ = fmt.Fprintln(os.Stderr, "Migrating legacy log config")
		migrateLegacyLogConfig(helper)
	} else if helper.GetNode("logging", "writers") == nil && (helper.GetNode("logging", "handlers") != nil) {
		_, _ = fmt.Fprintln(os.Stderr, "Migrating Python log config is not currently supported")
		// TODO implement?
		//migratePythonLogConfig(helper)
	} else {
		helper.Copy(up.Map, "logging")
	}
}

type legacyLogConfig struct {
	Directory       string `yaml:"directory"`
	FileNameFormat  string `yaml:"file_name_format"`
	FileDateFormat  string `yaml:"file_date_format"`
	FileMode        uint32 `yaml:"file_mode"`
	TimestampFormat string `yaml:"timestamp_format"`
	RawPrintLevel   string `yaml:"print_level"`
	JSONStdout      bool   `yaml:"print_json"`
	JSONFile        bool   `yaml:"file_json"`
}

func migrateLegacyLogConfig(helper *up.Helper) {
	var llc legacyLogConfig
	var newConfig zeroconfig.Config
	err := helper.GetBaseNode("logging").Decode(&newConfig)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Base config is corrupted: failed to decode example log config:", err)
		return
	} else if len(newConfig.Writers) != 2 || newConfig.Writers[0].Type != "stdout" || newConfig.Writers[1].Type != "file" {
		_, _ = fmt.Fprintln(os.Stderr, "Base log config is not in expected format")
		return
	}
	err = helper.GetNode("logging").Decode(&llc)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to decode legacy log config:", err)
		return
	}
	if llc.RawPrintLevel != "" {
		level, err := zerolog.ParseLevel(llc.RawPrintLevel)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Failed to parse minimum stdout log level:", err)
		} else {
			newConfig.Writers[0].MinLevel = &level
		}
	}
	if llc.Directory != "" && llc.FileNameFormat != "" {
		if llc.FileNameFormat == "{{.Date}}-{{.Index}}.log" {
			llc.FileNameFormat = "bridge.log"
		} else {
			llc.FileNameFormat = strings.ReplaceAll(llc.FileNameFormat, "{{.Date}}", "")
			llc.FileNameFormat = strings.ReplaceAll(llc.FileNameFormat, "{{.Index}}", "")
		}
		newConfig.Writers[1].Filename = filepath.Join(llc.Directory, llc.FileNameFormat)
	} else if llc.FileNameFormat == "" {
		newConfig.Writers = newConfig.Writers[0:1]
	}
	if llc.JSONStdout {
		newConfig.Writers[0].TimeFormat = ""
		newConfig.Writers[0].Format = "json"
	} else if llc.TimestampFormat != "" {
		newConfig.Writers[0].TimeFormat = llc.TimestampFormat
	}
	var updatedConfig yaml.Node
	err = updatedConfig.Encode(&newConfig)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to encode migrated log config:", err)
		return
	}
	*helper.GetBaseNode("logging").Node = updatedConfig
}

// Upgrader is a config upgrader that copies the default fields in the homeserver, appservice and logging blocks.
var Upgrader = up.SimpleUpgrader(doUpgrade)
