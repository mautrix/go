// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package format_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"

	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/format"
	"github.com/element-hq/mautrix-go/format/mdext"
)

func TestRenderMarkdown_PlainText(t *testing.T) {
	content := format.RenderMarkdown("hello world", true, true)
	assert.Equal(t, event.MessageEventContent{MsgType: event.MsgText, Body: "hello world"}, content)
	content = format.RenderMarkdown("hello world", true, false)
	assert.Equal(t, event.MessageEventContent{MsgType: event.MsgText, Body: "hello world"}, content)
	content = format.RenderMarkdown("hello world", false, true)
	assert.Equal(t, event.MessageEventContent{MsgType: event.MsgText, Body: "hello world"}, content)
	content = format.RenderMarkdown("<b>hello world</b>", false, false)
	assert.Equal(t, event.MessageEventContent{MsgType: event.MsgText, Body: "<b>hello world</b>"}, content)
}

func TestRenderMarkdown_EscapeHTML(t *testing.T) {
	content := format.RenderMarkdown("<b>hello world</b>", true, false)
	assert.Equal(t, event.MessageEventContent{
		MsgType:       event.MsgText,
		Body:          "<b>hello world</b>",
		Format:        event.FormatHTML,
		FormattedBody: "&lt;b&gt;hello world&lt;/b&gt;",
	}, content)
}

func TestRenderMarkdown_HTML(t *testing.T) {
	content := format.RenderMarkdown("<b>hello world</b>", false, true)
	assert.Equal(t, event.MessageEventContent{
		MsgType:       event.MsgText,
		Body:          "**hello world**",
		Format:        event.FormatHTML,
		FormattedBody: "<b>hello world</b>",
	}, content)

	content = format.RenderMarkdown("<b>hello world</b>", true, true)
	assert.Equal(t, event.MessageEventContent{
		MsgType:       event.MsgText,
		Body:          "**hello world**",
		Format:        event.FormatHTML,
		FormattedBody: "<b>hello world</b>",
	}, content)
}

var spoilerTests = map[string]string{
	"test ||bar||":            "test <span data-mx-spoiler>bar</span>",
	"test ||reason|**bar**||": `test <span data-mx-spoiler="reason"><strong>bar</strong></span>`,

	"test ||reason|[bar](https://example.com)||": `test <span data-mx-spoiler="reason"><a href="https://example.com">bar</a></span>`,
	"test [||reason|foo||](https://example.com)": `test <a href="https://example.com"><span data-mx-spoiler="reason">foo</span></a>`,
	"test [||foo||](https://example.com)":        `test <a href="https://example.com"><span data-mx-spoiler>foo</span></a>`,
	"test [||_foo_||](https://example.com)":      `test <a href="https://example.com"><span data-mx-spoiler><em>foo</em></span></a>`,
	// FIXME wrapping spoilers in italic/bold/strikethrough doesn't work for some reason
	//"test **[||foo||](https://example.com)**":    `test <strong><a href="https://example.com"><span data-mx-spoiler>foo</span></a></strong>`,
	//"test **||foo||**":                           `test <strong><span data-mx-spoiler><em>foo</span></strong>`,

	"* ||foo||": `<ul><li><span data-mx-spoiler>foo</span></li></ul>`,
	"> ||foo||": "<blockquote><p><span data-mx-spoiler>foo</span></p></blockquote>",
}

func TestRenderMarkdown_Spoiler(t *testing.T) {
	for markdown, html := range spoilerTests {
		rendered := format.RenderMarkdown(markdown, true, false)
		assert.Equal(t, markdown, rendered.Body)
		assert.Equal(t, html, strings.ReplaceAll(rendered.FormattedBody, "\n", ""))
	}
}

var simpleSpoilerTests = map[string]string{
	"test ||bar||":                          "test <span data-mx-spoiler>bar</span>",
	"test [||foo||](https://example.com)":   `test <a href="https://example.com"><span data-mx-spoiler>foo</span></a>`,
	"test [||*foo*||](https://example.com)": `test <a href="https://example.com"><span data-mx-spoiler><em>foo</em></span></a>`,
	"* ||foo||":                             `<ul><li><span data-mx-spoiler>foo</span></li></ul>`,
	"> ||foo||":                             "<blockquote><p><span data-mx-spoiler>foo</span></p></blockquote>",

	// Simple spoiler renderer supports wrapping fully already
	"test **[||foo||](https://example.com)**": `test <strong><a href="https://example.com"><span data-mx-spoiler>foo</span></a></strong>`,
	"test **||foo||**":                        `test <strong><span data-mx-spoiler>foo</span></strong>`,
	"test **||*foo*||**":                      `test <strong><span data-mx-spoiler><em>foo</em></span></strong>`,
	"test ~~**||*foo*||**~~":                  `test <del><strong><span data-mx-spoiler><em>foo</em></span></strong></del>`,
	"> ||~~***foo***~~||":                     "<blockquote><p><span data-mx-spoiler><del><em><strong>foo</strong></em></del></span></p></blockquote>",

	"a \\||test||": "a ||test||",
	"\\~~test~~":   "~~test~~",
	"\\*test* hmm": "*test* hmm",
}

func render(renderer goldmark.Markdown, text string) string {
	var buf strings.Builder
	err := renderer.Convert([]byte(text), &buf)
	if err != nil {
		panic(err)
	}
	return buf.String()
}

func TestRenderMarkdown_SimpleSpoiler(t *testing.T) {
	renderer := goldmark.New(goldmark.WithExtensions(extension.Strikethrough, mdext.SimpleSpoiler, mdext.EscapeHTML), format.HTMLOptions)
	for markdown, html := range simpleSpoilerTests {
		rendered := format.UnwrapSingleParagraph(render(renderer, markdown))
		assert.Equal(t, html, strings.ReplaceAll(rendered, "\n", ""))
	}
}

var discordUnderlineTests = map[string]string{
	"**test**":           "<strong>test</strong>",
	"*test*":             "<em>test</em>",
	"_test_":             "<em>test</em>",
	"__test__":           "<u>test</u>",
	"__*test*__":         "<u><em>test</em></u>",
	"___test___":         "<em><u>test</u></em>",
	"____test____":       "<u><u>test</u></u>",
	"**__test__**":       "<strong><u>test</u></strong>",
	"__***test***__":     "<u><em><strong>test</strong></em></u>",
	"__~~***test***~~__": "<u><del><em><strong>test</strong></em></del></u>",

	//"\\__test__":         "__test__",
	//"\\**test**":         "**test**",
}

func TestRenderMarkdown_DiscordUnderline(t *testing.T) {
	renderer := goldmark.New(goldmark.WithExtensions(extension.Strikethrough, mdext.DiscordUnderline, mdext.EscapeHTML), format.HTMLOptions)
	for markdown, html := range discordUnderlineTests {
		rendered := format.UnwrapSingleParagraph(render(renderer, markdown))
		assert.Equal(t, html, strings.ReplaceAll(rendered, "\n", ""))
	}
}
