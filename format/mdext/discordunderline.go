// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mdext

import (
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

type astDiscordUnderline struct {
	ast.BaseInline
}

func (n *astDiscordUnderline) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, nil, nil)
}

var astKindDiscordUnderline = ast.NewNodeKind("DiscordUnderline")

func (n *astDiscordUnderline) Kind() ast.NodeKind {
	return astKindDiscordUnderline
}

type discordUnderlineDelimiterProcessor struct{}

func (p *discordUnderlineDelimiterProcessor) IsDelimiter(b byte) bool {
	return b == '_'
}

func (p *discordUnderlineDelimiterProcessor) CanOpenCloser(opener, closer *parser.Delimiter) bool {
	return opener.Char == closer.Char
}

func (p *discordUnderlineDelimiterProcessor) OnMatch(consumes int) ast.Node {
	if consumes == 1 {
		// Slightly hacky hack: if the delimiter parser tries to give us text wrapped with a single underline,
		// send it over to the emphasis area instead of returning an underline node.
		return ast.NewEmphasis(consumes)
	}
	return &astDiscordUnderline{}
}

var defaultDiscordUnderlineDelimiterProcessor = &discordUnderlineDelimiterProcessor{}

type discordUnderlineParser struct{}

var defaultDiscordUnderlineParser = &discordUnderlineParser{}

// NewDiscordUnderlineParser return a new InlineParser that parses
// Discord underline expressions.
func NewDiscordUnderlineParser() parser.InlineParser {
	return defaultDiscordUnderlineParser
}

func (s *discordUnderlineParser) Trigger() []byte {
	return []byte{'_'}
}

func (s *discordUnderlineParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	before := block.PrecendingCharacter()
	line, segment := block.PeekLine()
	node := parser.ScanDelimiter(line, before, 2, defaultDiscordUnderlineDelimiterProcessor)
	if node == nil {
		return nil
	}
	node.Segment = segment.WithStop(segment.Start + node.OriginalLength)
	block.Advance(node.OriginalLength)
	pc.PushDelimiter(node)
	return node
}

func (s *discordUnderlineParser) CloseBlock(parent ast.Node, pc parser.Context) {
	// nothing to do
}

// discordUnderlineHTMLRenderer is a renderer.NodeRenderer implementation that
// renders discord underline nodes.
type discordUnderlineHTMLRenderer struct {
	html.Config
}

// NewDiscordUnderlineHTMLRenderer returns a new discordUnderlineHTMLRenderer.
func NewDiscordUnderlineHTMLRenderer(opts ...html.Option) renderer.NodeRenderer {
	r := &discordUnderlineHTMLRenderer{
		Config: html.NewConfig(),
	}
	for _, opt := range opts {
		opt.SetHTMLOption(&r.Config)
	}
	return r
}

func (r *discordUnderlineHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(astKindDiscordUnderline, r.renderDiscordUnderline)
}

var DiscordUnderlineAttributeFilter = html.GlobalAttributeFilter

func (r *discordUnderlineHTMLRenderer) renderDiscordUnderline(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		if n.Attributes() != nil {
			_, _ = w.WriteString("<u")
			html.RenderAttributes(w, n, DiscordUnderlineAttributeFilter)
			_ = w.WriteByte('>')
		} else {
			_, _ = w.WriteString("<u>")
		}
	} else {
		_, _ = w.WriteString("</u>")
	}
	return ast.WalkContinue, nil
}

type discordUnderline struct{}

// DiscordUnderline is an extension that allow you to use underline expression like '__text__' .
var DiscordUnderline = &discordUnderline{}

func (e *discordUnderline) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithInlineParsers(
		// This must be a higher priority (= lower priority number) than the emphasis parser
		// in https://github.com/yuin/goldmark/blob/v1.4.12/parser/parser.go#L601
		util.Prioritized(NewDiscordUnderlineParser(), 450),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(NewDiscordUnderlineHTMLRenderer(), 500),
	))
}
