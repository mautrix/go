// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mdext

import (
	"bytes"
	"fmt"
	stdhtml "html"
	"regexp"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

var astKindSpoiler = ast.NewNodeKind("Spoiler")

type astSpoiler struct {
	ast.BaseInline
	reason string
}

func (n *astSpoiler) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, nil, nil)
}

func (n *astSpoiler) Kind() ast.NodeKind {
	return astKindSpoiler
}

type spoilerDelimiterProcessor struct{}

var defaultSpoilerDelimiterProcessor = &spoilerDelimiterProcessor{}

func (p *spoilerDelimiterProcessor) IsDelimiter(b byte) bool {
	return b == '|'
}

func (p *spoilerDelimiterProcessor) CanOpenCloser(opener, closer *parser.Delimiter) bool {
	return opener.Char == closer.Char
}

func (p *spoilerDelimiterProcessor) OnMatch(consumes int) ast.Node {
	return &astSpoiler{}
}

type spoilerParser struct{}

var defaultSpoilerParser = &spoilerParser{}

func NewSpoilerParser() parser.InlineParser {
	return defaultSpoilerParser
}

func (s *spoilerParser) Trigger() []byte {
	return []byte{'|'}
}

var spoilerRegex = regexp.MustCompile(`^\|\|(?:([^|]+?)\|[^|])?`)
var spoilerContextKey = parser.NewContextKey()

type spoilerContext struct {
	reason  string
	segment text.Segment
	bottom  *parser.Delimiter
}

func (s *spoilerParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	line, segment := block.PeekLine()
	if spoiler, ok := pc.Get(spoilerContextKey).(spoilerContext); ok {
		if !bytes.HasPrefix(line, []byte("||")) {
			return nil
		}
		block.Advance(2)
		pc.Set(spoilerContextKey, nil)
		n := &astSpoiler{
			BaseInline: ast.BaseInline{},
			reason:     spoiler.reason,
		}
		parser.ProcessDelimiters(spoiler.bottom, pc)
		var c ast.Node = spoiler.bottom
		for c != nil {
			next := c.NextSibling()
			parent.RemoveChild(parent, c)
			n.AppendChild(n, c)
			c = next
		}
		return n
	}
	match := spoilerRegex.FindSubmatch(line)
	if match == nil {
		return nil
	}
	length := 2
	reason := string(match[1])
	if len(reason) > 0 {
		length += len(match[1]) + 1
	}
	block.Advance(length)
	delim := parser.NewDelimiter(true, false, length, '|', defaultSpoilerDelimiterProcessor)
	pc.Set(spoilerContextKey, spoilerContext{
		reason:  reason,
		segment: segment,
		bottom:  delim,
	})
	return delim
}

func (s *spoilerParser) CloseBlock(parent ast.Node, pc parser.Context) {
	// nothing to do
}

type spoilerHTMLRenderer struct {
	html.Config
}

func NewSpoilerHTMLRenderer(opts ...html.Option) renderer.NodeRenderer {
	r := &spoilerHTMLRenderer{
		Config: html.NewConfig(),
	}
	for _, opt := range opts {
		opt.SetHTMLOption(&r.Config)
	}
	return r
}

func (r *spoilerHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(astKindSpoiler, r.renderSpoiler)
}

func (r *spoilerHTMLRenderer) renderSpoiler(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		node := n.(*astSpoiler)
		if len(node.reason) == 0 {
			_, _ = w.WriteString("<span data-mx-spoiler>")
		} else {
			_, _ = fmt.Fprintf(w, `<span data-mx-spoiler="%s">`, stdhtml.EscapeString(node.reason))
		}
	} else {
		_, _ = w.WriteString("</span>")
	}
	return ast.WalkContinue, nil
}

type extSpoiler struct{}

// Spoiler is an extension that allow you to use spoiler expression like '||text||' or ||reason|text|| .
//
// There are some types of nested formatting that aren't supported with advanced spoilers.
// The SimpleSpoiler extension that doesn't support reasons can be used to work around those.
var Spoiler = &extSpoiler{}

func (e *extSpoiler) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithInlineParsers(
		util.Prioritized(NewSpoilerParser(), 500),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(NewSpoilerHTMLRenderer(), 500),
	))
}
