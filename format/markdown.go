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

	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/format/mdext"
)

const paragraphStart = "<p>"
const paragraphEnd = "</p>"

var Extensions = goldmark.WithExtensions(extension.Strikethrough, extension.Table, mdext.Spoiler)
var HTMLOptions = goldmark.WithRendererOptions(html.WithHardWraps(), html.WithUnsafe())

var withHTML = goldmark.New(Extensions, HTMLOptions)
var noHTML = goldmark.New(Extensions, HTMLOptions, goldmark.WithExtensions(mdext.EscapeHTML))

// UnwrapSingleParagraph removes paragraph tags surrounding a string if the string only contains a single paragraph.
func UnwrapSingleParagraph(html string) string {
	html = strings.TrimRight(html, "\n")
	if strings.HasPrefix(html, paragraphStart) && strings.HasSuffix(html, paragraphEnd) {
		htmlBodyWithoutP := html[len(paragraphStart) : len(html)-len(paragraphEnd)]
		if !strings.Contains(htmlBodyWithoutP, paragraphStart) {
			return htmlBodyWithoutP
		}
	}
	return html
}

func RenderMarkdownCustom(text string, renderer goldmark.Markdown) event.MessageEventContent {
	var buf strings.Builder
	err := renderer.Convert([]byte(text), &buf)
	if err != nil {
		panic(fmt.Errorf("markdown parser errored: %w", err))
	}
	htmlBody := UnwrapSingleParagraph(buf.String())
	return HTMLToContent(htmlBody)
}

func HTMLToContent(html string) event.MessageEventContent {
	text := HTMLToMarkdown(html)
	if html != text {
		return event.MessageEventContent{
			FormattedBody: html,
			Format:        event.FormatHTML,
			MsgType:       event.MsgText,
			Body:          text,
		}
	}
	return event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    text,
	}
}

func RenderMarkdown(text string, allowMarkdown, allowHTML bool) event.MessageEventContent {
	var htmlBody string

	if allowMarkdown {
		rndr := withHTML
		if !allowHTML {
			rndr = noHTML
		}
		return RenderMarkdownCustom(text, rndr)
	} else if allowHTML {
		htmlBody = strings.Replace(text, "\n", "<br>", -1)
		return HTMLToContent(htmlBody)
	} else {
		return event.MessageEventContent{
			MsgType: event.MsgText,
			Body:    text,
		}
	}
}
