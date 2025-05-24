// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package format

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
	"go.mau.fi/util/exstrings"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format/mdext"
	"maunium.net/go/mautrix/id"
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

var mdEscapeRegex = regexp.MustCompile("([\\\\`*_[\\]()])")

func EscapeMarkdown(text string) string {
	text = mdEscapeRegex.ReplaceAllString(text, "\\$1")
	text = strings.ReplaceAll(text, ">", "&gt;")
	text = strings.ReplaceAll(text, "<", "&lt;")
	return text
}

type uriAble interface {
	String() string
	URI() *id.MatrixURI
}

func MarkdownMention(id uriAble) string {
	return MarkdownLink(id.String(), id.URI().MatrixToURL())
}

func MarkdownLink(name string, url string) string {
	return fmt.Sprintf("[%s](%s)", EscapeMarkdown(name), EscapeMarkdown(url))
}

func SafeMarkdownCode[T ~string](textInput T) string {
	if textInput == "" {
		return "` `"
	}
	text := strings.ReplaceAll(string(textInput), "\n", " ")
	backtickCount := exstrings.LongestSequenceOf(text, '`')
	if backtickCount == 0 {
		return fmt.Sprintf("`%s`", text)
	}
	quotes := strings.Repeat("`", backtickCount+1)
	if text[0] == '`' || text[len(text)-1] == '`' {
		return fmt.Sprintf("%s %s %s", quotes, text, quotes)
	}
	return fmt.Sprintf("%s%s%s", quotes, text, quotes)
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

func TextToContent(text string) event.MessageEventContent {
	return event.MessageEventContent{
		MsgType:  event.MsgText,
		Body:     text,
		Mentions: &event.Mentions{},
	}
}

func HTMLToContentFull(renderer *HTMLParser, html string) event.MessageEventContent {
	text, mentions := HTMLToMarkdownFull(renderer, html)
	if html != text {
		return event.MessageEventContent{
			FormattedBody: html,
			Format:        event.FormatHTML,
			MsgType:       event.MsgText,
			Body:          text,
			Mentions:      mentions,
		}
	}
	return TextToContent(text)
}

func HTMLToContent(html string) event.MessageEventContent {
	return HTMLToContentFull(nil, html)
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
		return TextToContent(text)
	}
}
