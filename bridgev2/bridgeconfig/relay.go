// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
)

type RelayConfig struct {
	Enabled           bool                         `yaml:"enabled"`
	AdminOnly         bool                         `yaml:"admin_only"`
	DefaultRelays     []networkid.UserLoginID      `yaml:"default_relays"`
	MessageFormats    map[event.MessageType]string `yaml:"message_formats"`
	DisplaynameFormat string                       `yaml:"displayname_format"`
	messageTemplates  *template.Template           `yaml:"-"`
	nameTemplate      *template.Template           `yaml:"-"`
}

type umRelayConfig RelayConfig

func (rc *RelayConfig) UnmarshalYAML(node *yaml.Node) error {
	err := node.Decode((*umRelayConfig)(rc))
	if err != nil {
		return err
	}

	rc.messageTemplates = template.New("messageTemplates")
	for key, template := range rc.MessageFormats {
		_, err = rc.messageTemplates.New(string(key)).Parse(template)
		if err != nil {
			return err
		}
	}

	rc.nameTemplate, err = template.New("nameTemplate").Parse(rc.DisplaynameFormat)
	if err != nil {
		return err
	}

	return nil
}

type formatData struct {
	Sender   any
	Content  *event.MessageEventContent
	Caption  string
	Message  string
	FileName string
}

func isMedia(msgType event.MessageType) bool {
	switch msgType {
	case event.MsgImage, event.MsgVideo, event.MsgAudio, event.MsgFile:
		return true
	default:
		return false
	}
}

func (rc *RelayConfig) FormatMessage(content *event.MessageEventContent, sender any) (*event.MessageEventContent, error) {
	_, isSupported := rc.MessageFormats[content.MsgType]
	if !isSupported {
		return nil, fmt.Errorf("unsupported msgtype for relaying")
	}
	contentCopy := *content
	content = &contentCopy
	content.EnsureHasHTML()
	fd := &formatData{
		Sender:  sender,
		Content: content,
		Message: content.FormattedBody,
	}
	fd.Message = content.FormattedBody
	if content.FileName != "" {
		fd.FileName = content.FileName
		if content.FileName != content.Body {
			fd.Caption = fd.Message
		}
	} else if isMedia(content.MsgType) {
		content.FileName = content.Body
		fd.FileName = content.Body
	}
	var output strings.Builder
	err := rc.messageTemplates.ExecuteTemplate(&output, string(content.MsgType), fd)
	if err != nil {
		return nil, err
	}
	content.FormattedBody = output.String()
	content.Body = format.HTMLToText(content.FormattedBody)
	return content, nil
}

func (rc *RelayConfig) FormatName(sender any) string {
	var buf strings.Builder
	_ = rc.nameTemplate.Execute(&buf, sender)
	return strings.TrimSpace(buf.String())
}
