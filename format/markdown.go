// Copyright 2018 Tulir Asokan
package format

import (
	"io"
	"regexp"
	"strings"

	"github.com/russross/blackfriday/v2"

	"maunium.net/go/mautrix"
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

func RenderMarkdown(text string, allowMarkdown, allowHTML bool) mautrix.Content {
	htmlBody := text

	if allowMarkdown {
		renderer := Renderer
		if !allowHTML {
			renderer = NoHTMLRenderer
		}
		htmlBodyBytes := blackfriday.Run([]byte(text), Extensions, renderer)
		htmlBody = strings.TrimRight(string(htmlBodyBytes), "\n")
		htmlBody = AntiParagraphRegex.ReplaceAllString(htmlBody, "$1")
	}

	if allowHTML || allowMarkdown {
		text = HTMLToText(htmlBody)

		if htmlBody != text {
			return mautrix.Content{
				FormattedBody: htmlBody,
				Format:        mautrix.FormatHTML,
				MsgType:       mautrix.MsgText,
				Body:          text,
			}
		}
	}

	return mautrix.Content{
		MsgType: mautrix.MsgText,
		Body:    text,
	}
}
