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

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/format/mdext"
	"maunium.net/go/mautrix/id"
)

func TestRenderMarkdown_PlainText(t *testing.T) {
	content := format.RenderMarkdown("hello world", true, true)
	assert.Equal(t, event.MessageEventContent{MsgType: event.MsgText, Body: "hello world", Mentions: &event.Mentions{}}, content)
	content = format.RenderMarkdown("hello world", true, false)
	assert.Equal(t, event.MessageEventContent{MsgType: event.MsgText, Body: "hello world", Mentions: &event.Mentions{}}, content)
	content = format.RenderMarkdown("hello world", false, true)
	assert.Equal(t, event.MessageEventContent{MsgType: event.MsgText, Body: "hello world", Mentions: &event.Mentions{}}, content)
	content = format.RenderMarkdown("<b>hello world</b>", false, false)
	assert.Equal(t, event.MessageEventContent{MsgType: event.MsgText, Body: "<b>hello world</b>", Mentions: &event.Mentions{}}, content)
	content = format.RenderMarkdown(`<a href="https://matrix.to/#/@user:example.com">mention</a>`, false, false)
	assert.Equal(t, event.MessageEventContent{MsgType: event.MsgText, Body: "<a href=\"https://matrix.to/#/@user:example.com\">mention</a>", Mentions: &event.Mentions{}}, content)
}

func TestRenderMarkdown_EscapeHTML(t *testing.T) {
	content := format.RenderMarkdown("<b>hello world</b>", true, false)
	assert.Equal(t, event.MessageEventContent{
		MsgType:       event.MsgText,
		Body:          "<b>hello world</b>",
		Format:        event.FormatHTML,
		FormattedBody: "&lt;b&gt;hello world&lt;/b&gt;",
		Mentions:      &event.Mentions{},
	}, content)
}

func TestRenderMarkdown_HTML(t *testing.T) {
	content := format.RenderMarkdown("<b>hello world</b>", false, true)
	assert.Equal(t, event.MessageEventContent{
		MsgType:       event.MsgText,
		Body:          "**hello world**",
		Format:        event.FormatHTML,
		FormattedBody: "<b>hello world</b>",
		Mentions:      &event.Mentions{},
	}, content)

	content = format.RenderMarkdown("<b>hello world</b>", true, true)
	assert.Equal(t, event.MessageEventContent{
		MsgType:       event.MsgText,
		Body:          "**hello world**",
		Format:        event.FormatHTML,
		FormattedBody: "<b>hello world</b>",
		Mentions:      &event.Mentions{},
	}, content)

	content = format.RenderMarkdown(`[mention](https://matrix.to/#/@user:example.com)`, true, false)
	assert.Equal(t, event.MessageEventContent{
		MsgType:       event.MsgText,
		Body:          "mention",
		Format:        event.FormatHTML,
		FormattedBody: `<a href="https://matrix.to/#/@user:example.com">mention</a>`,
		Mentions: &event.Mentions{
			UserIDs: []id.UserID{"@user:example.com"},
		},
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

var mathTests = map[string]string{
	"$foo$":              `<span data-mx-maths="foo"><code>foo</code></span>`,
	"hello $foo$ world":  `hello <span data-mx-maths="foo"><code>foo</code></span> world`,
	"$$\nfoo\nbar\n$$":   `<div data-mx-maths="foo\nbar"><code>foo<br>bar</code></div>`,
	"`$foo$`":            `<code>$foo$</code>`,
	"```\n$foo$\n```":    `<pre><code>$foo$\n</code></pre>`,
	"~~meow $foo$ asd~~": `<del>meow <span data-mx-maths="foo"><code>foo</code></span> asd</del>`,
	"$5 or $10":          `$5 or $10`,
	"5$ or 10$":          `5$ or 10$`,
	"$5 or 10$":          `<span data-mx-maths="5 or 10"><code>5 or 10</code></span>`,
	"$*500*$":            `<span data-mx-maths="*500*"><code>*500*</code></span>`,
	"$$\n*500*\n$$":      `<div data-mx-maths="*500*"><code>*500*</code></div>`,

	// TODO: This doesn't work :(
	// Maybe same reason as the spoiler wrapping not working?
	//"~~$foo$~~": `<del><span data-mx-maths="foo"><code>foo</code></span></del>`,
}

func TestRenderMarkdown_Math(t *testing.T) {
	renderer := goldmark.New(goldmark.WithExtensions(extension.Strikethrough, mdext.Math, mdext.EscapeHTML), format.HTMLOptions)
	for markdown, html := range mathTests {
		rendered := format.UnwrapSingleParagraph(render(renderer, markdown))
		assert.Equal(t, html, strings.ReplaceAll(rendered, "\n", "\\n"), "with input %q", markdown)
	}
}

var customEmojiTests = map[string]string{
	`![:meow:](mxc://example.com/emoji.png "Emoji: meow")`: `<img src="mxc://example.com/emoji.png" alt=":meow:" title="meow" data-mx-emoticon="" height="32">`,
}

func TestRenderMarkdown_CustomEmoji(t *testing.T) {
	renderer := goldmark.New(goldmark.WithExtensions(mdext.CustomEmoji), format.HTMLOptions)
	for markdown, html := range customEmojiTests {
		rendered := format.UnwrapSingleParagraph(render(renderer, markdown))
		assert.Equal(t, html, rendered, "with input %q", markdown)
	}
}

var codeTests = map[string]string{
	"meow":      "`meow`",
	"me`ow":     "``me`ow``",
	"`me`ow":    "`` `me`ow ``",
	"me`ow`":    "`` me`ow` ``",
	"`meow`":    "`` `meow` ``",
	"`````````": "`````````` ````````` ``````````",
}

func TestSafeMarkdownCode(t *testing.T) {
	for input, expected := range codeTests {
		assert.Equal(t, expected, format.SafeMarkdownCode(input), "with input %q", input)
	}
}
