// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/event"
)

func TestCheckMessageContentCaps_ViewOnce(t *testing.T) {
	caps := &event.RoomFeatures{
		File: event.FileFeatureMap{
			event.MsgImage: {
				MimeTypes: map[string]event.CapabilitySupportLevel{"image/jpeg": event.CapLevelFullySupported},
				ViewOnce:  true,
			},
			event.MsgFile: {
				MimeTypes: map[string]event.CapabilitySupportLevel{"*/*": event.CapLevelFullySupported},
			},
		},
	}
	image := &event.MessageEventContent{MsgType: event.MsgImage, Body: "a.jpg", Info: &event.FileInfo{MimeType: "image/jpeg"}}
	file := &event.MessageEventContent{MsgType: event.MsgFile, Body: "a.jpg", Info: &event.FileInfo{MimeType: "image/jpeg"}}
	text := &event.MessageEventContent{MsgType: event.MsgText, Body: "hi"}

	portal := &Portal{}
	for _, content := range []*event.MessageEventContent{image, file, text} {
		assert.NoError(t, portal.checkMessageContentCaps(caps, content), content.MsgType)
		viewOnce := *content
		viewOnce.BeeperViewOnce = true
		err := portal.checkMessageContentCaps(caps, &viewOnce)
		if content == image {
			assert.NoError(t, err)
		} else {
			assert.ErrorIs(t, err, ErrViewOnceNotAllowed, content.MsgType)
		}
	}
}
