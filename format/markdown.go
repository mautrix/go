// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package format

import (
	"io"
	"regexp"
	"strings"

	"github.com/russross/blackfriday/v2"

	"maunium.net/go/mautrix/event"
)

type EscapingRenderer struct {
	*blackfriday.HTMLRenderer
}

func (r *EscapingRenderer) RenderNode(w io.Writer, node *blackfriday.Node, entering bool) blackfriday.WalkStatus {
	if node.Type == blackfriday.HTMLSpan {
		node.Type = blackfriday.Text
	}
	return r.HTMLRenderer.RenderNode(w, node, entering)
}

var AntiParagraphRegex = regexp.MustCompile("^<p>(.+?)</p>$")
var Extensions = blackfriday.WithExtensions(blackfriday.NoIntraEmphasis |
	blackfriday.Tables |
	blackfriday.FencedCode |
	blackfriday.Strikethrough |
	blackfriday.SpaceHeadings |
	blackfriday.DefinitionLists |
	blackfriday.HardLineBreak)
var bfhtml = blackfriday.NewHTMLRenderer(blackfriday.HTMLRendererParameters{
	Flags: blackfriday.UseXHTML,
})
var Renderer = blackfriday.WithRenderer(bfhtml)
var NoHTMLRenderer = blackfriday.WithRenderer(&EscapingRenderer{bfhtml})

func RenderMarkdown(text string, allowMarkdown, allowHTML bool) event.MessageEventContent {
	var htmlBody string

	if allowMarkdown {
		renderer := Renderer
		if !allowHTML {
			renderer = NoHTMLRenderer
		}
		htmlBodyBytes := blackfriday.Run([]byte(text), Extensions, renderer)
		htmlBody = strings.TrimRight(string(htmlBodyBytes), "\n")
		htmlBody = AntiParagraphRegex.ReplaceAllString(htmlBody, "$1")
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
