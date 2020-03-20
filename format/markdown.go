// Copyright 2018 Tulir Asokan
package format

import (
	"regexp"
	"strings"

	"github.com/russross/blackfriday/v2"

	"maunium.net/go/mautrix"
)

var AntiParagraphRegex = regexp.MustCompile("^<p>(.+?)</p>$")
var Extensions = blackfriday.WithExtensions(blackfriday.NoIntraEmphasis |
	blackfriday.Tables |
	blackfriday.FencedCode |
	blackfriday.Strikethrough |
	blackfriday.SpaceHeadings |
	blackfriday.DefinitionLists |
	blackfriday.HardLineBreak)
var Renderer = blackfriday.WithRenderer(blackfriday.NewHTMLRenderer(blackfriday.HTMLRendererParameters{
	Flags: blackfriday.UseXHTML,
}))

func RenderMarkdown(text string) mautrix.Content {
	htmlBodyBytes := blackfriday.Run([]byte(text), Extensions, Renderer)
	htmlBody := strings.TrimRight(string(htmlBodyBytes), "\n")
	htmlBody = AntiParagraphRegex.ReplaceAllString(htmlBody, "$1")

	text = HTMLToText(htmlBody)

	if htmlBody == text {
		return mautrix.Content{
			MsgType: mautrix.MsgText,
			Body:    text,
		}
	}

	return mautrix.Content{
		FormattedBody: htmlBody,
		Format:        mautrix.FormatHTML,
		MsgType:       mautrix.MsgText,
		Body:          text,
	}
}
