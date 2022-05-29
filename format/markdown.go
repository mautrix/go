// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package format

import (
	"fmt"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"

	"maunium.net/go/mautrix/event"
)

const paragraphStart = "<p>"
const paragraphEnd = "</p>"

var Extensions = goldmark.WithExtensions(extension.Strikethrough, extension.Table, ExtensionSpoiler)
var HTMLOptions = goldmark.WithRendererOptions(html.WithHardWraps(), html.WithUnsafe())

var withHTML = goldmark.New(Extensions, HTMLOptions)
var noHTML = goldmark.New(Extensions, HTMLOptions, goldmark.WithExtensions(ExtensionEscapeHTML))

// UnwrapSingleParagraph removes paragraph tags surrounding a string if the string only contains a single paragraph.
func UnwrapSingleParagraph(html string) string {
	if strings.HasPrefix(html, paragraphStart) && strings.HasSuffix(html, paragraphEnd) {
		htmlBodyWithoutP := html[len(paragraphStart) : len(html)-len(paragraphEnd)]
		if !strings.Contains(htmlBodyWithoutP, paragraphStart) {
			return htmlBodyWithoutP
		}
	}
	return html
}

func RenderMarkdown(text string, allowMarkdown, allowHTML bool) event.MessageEventContent {
	var htmlBody string

	if allowMarkdown {
		rndr := withHTML
		if !allowHTML {
			rndr = noHTML
		}
		var buf strings.Builder
		err := rndr.Convert([]byte(text), &buf)
		if err != nil {
			panic(fmt.Errorf("markdown parser errored: %w", err))
		}
		htmlBody = strings.TrimRight(buf.String(), "\n")
		htmlBody = UnwrapSingleParagraph(htmlBody)
	} else {
		htmlBody = strings.Replace(text, "\n", "<br>", -1)
	}

	if len(htmlBody) > 0 && (allowMarkdown || allowHTML) {
		text = HTMLToText(htmlBody)

		if htmlBody != text {
			return event.MessageEventContent{
				FormattedBody: htmlBody,
				Format:        event.FormatHTML,
				MsgType:       event.MsgText,
				Body:          text,
			}
		}
	}

	return event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    text,
	}
}
