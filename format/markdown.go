// Copyright 2018 Tulir Asokan
package format

import (
	"github.com/russross/blackfriday/v2"

	"maunium.net/go/mautrix"
)

func RenderMarkdown(text string) mautrix.Content {
	htmlBody := blackfriday.Run([]byte(text),
		blackfriday.WithExtensions(blackfriday.NoIntraEmphasis|
			blackfriday.Tables|
			blackfriday.FencedCode|
			blackfriday.Strikethrough|
			blackfriday.SpaceHeadings|
			blackfriday.DefinitionLists|
			blackfriday.HardLineBreak),
		blackfriday.WithRenderer(blackfriday.NewHTMLRenderer(blackfriday.HTMLRendererParameters{
			Flags: blackfriday.UseXHTML,
		})))
	//htmlBody := strings.ReplaceAll(string(htmlBodyBytes), "\n", "")

	return mautrix.Content{
		FormattedBody: string(htmlBody),
		Format:        mautrix.FormatHTML,
		MsgType:       mautrix.MsgText,
		Body:          HTMLToText(string(htmlBody)),
	}
}
