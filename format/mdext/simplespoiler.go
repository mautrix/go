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
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

type simpleSpoilerParser struct{}

var defaultSimpleSpoilerParser = &simpleSpoilerParser{}

func NewSimpleSpoilerParser() parser.InlineParser {
	return defaultSimpleSpoilerParser
}

func (s *simpleSpoilerParser) Trigger() []byte {
	return []byte{'|'}
}

func (s *simpleSpoilerParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	// This is basically copied from https://github.com/yuin/goldmark/blob/master/extension/strikethrough.go
	before := block.PrecendingCharacter()
	line, segment := block.PeekLine()
	node := parser.ScanDelimiter(line, before, 2, defaultSpoilerDelimiterProcessor)
	if node == nil {
		return nil
	}
	node.Segment = segment.WithStop(segment.Start + node.OriginalLength)
	block.Advance(node.OriginalLength)
	pc.PushDelimiter(node)
	return node
}

func (s *simpleSpoilerParser) CloseBlock(parent ast.Node, pc parser.Context) {
	// nothing to do
}

type simpleSpoiler struct{}

// SimpleSpoiler is an extension that allow you to use simple spoiler expression like '||text||' .
//
// For spoilers with reasons ('||reason|text||'), use the Spoiler extension.
var SimpleSpoiler = &simpleSpoiler{}

func (e *simpleSpoiler) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithInlineParsers(
		util.Prioritized(NewSimpleSpoilerParser(), 500),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(NewSpoilerHTMLRenderer(), 500),
	))
}
