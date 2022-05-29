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

	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/format/mdext"
)

var spoilerTests = map[string]string{
	"test ||bar||":            "test <span data-mx-spoiler>bar</span>",
	"test ||reason|**bar**||": `test <span data-mx-spoiler="reason"><strong>bar</strong></span>`,

	"test ||reason|[bar](https://example.com)||": `test <span data-mx-spoiler="reason"><a href="https://example.com">bar</a></span>`,
	"test [||reason|foo||](https://example.com)": `test <a href="https://example.com"><span data-mx-spoiler="reason">foo</span></a>`,
	"test [||foo||](https://example.com)":        `test <a href="https://example.com"><span data-mx-spoiler>foo</span></a>`,
	"test [||*foo*||](https://example.com)":      `test <a href="https://example.com"><span data-mx-spoiler><em>foo</em></span></a>`,
	// FIXME wrapping spoilers in italic/bold/strikethrough doesn't work for some reason
	//"test **[||foo||](https://example.com)**":    `test <strong><a href="https://example.com"><span data-mx-spoiler>foo</span></a></strong>`,
	//"test **||foo||**":                           `test <strong><span data-mx-spoiler><em>foo</span></strong>`,

	"* ||foo||": `<ul><li><span data-mx-spoiler>foo</span></li></ul>`,
	"> ||foo||": "<blockquote><p><span data-mx-spoiler>foo</span></p></blockquote>",
}

func TestRenderMarkdown_Spoiler(t *testing.T) {
	for markdown, html := range spoilerTests {
		rendered := format.RenderMarkdown(markdown, true, false)
		// FIXME the HTML parser doesn't do spoilers yet
		//assert.Equal(t, plaintext, rendered.Body)
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
}

func TestRenderMarkdown_SimpleSpoiler(t *testing.T) {
	renderer := goldmark.New(goldmark.WithExtensions(extension.Strikethrough, extension.Table, mdext.SimpleSpoiler, mdext.EscapeHTML), format.HTMLOptions)
	render := func(text string) string {
		var buf strings.Builder
		err := renderer.Convert([]byte(text), &buf)
		if err != nil {
			panic(err)
		}
		return buf.String()
	}
	for markdown, html := range simpleSpoilerTests {
		rendered := format.UnwrapSingleParagraph(render(markdown))
		assert.Equal(t, html, strings.ReplaceAll(rendered, "\n", ""))
	}
}
