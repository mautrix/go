// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mdext

import (
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

var ShortEmphasis goldmark.Extender = &shortEmphasisExtender{}

type shortEmphasisExtender struct{}

func (s *shortEmphasisExtender) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithInlineParsers(
		util.Prioritized(&italicsParser{}, 500),
		util.Prioritized(&boldParser{}, 500),
	))
}

type italicsDelimiterProcessor struct{}

func (p *italicsDelimiterProcessor) IsDelimiter(b byte) bool {
	return b == '_'
}

func (p *italicsDelimiterProcessor) CanOpenCloser(opener, closer *parser.Delimiter) bool {
	return opener.Char == closer.Char
}

func (p *italicsDelimiterProcessor) OnMatch(consumes int) ast.Node {
	return ast.NewEmphasis(1)
}

var defaultItalicsDelimiterProcessor = &italicsDelimiterProcessor{}

type italicsParser struct{}

func (s *italicsParser) Trigger() []byte {
	return []byte{'_'}
}

func (s *italicsParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	before := block.PrecendingCharacter()
	line, segment := block.PeekLine()
	node := parser.ScanDelimiter(line, before, 1, defaultItalicsDelimiterProcessor)
	if node == nil || node.OriginalLength > 1 || before == '_' {
		return nil
	}
	node.Segment = segment.WithStop(segment.Start + node.OriginalLength)
	block.Advance(node.OriginalLength)
	pc.PushDelimiter(node)
	return node
}

type boldDelimiterProcessor struct{}

func (p *boldDelimiterProcessor) IsDelimiter(b byte) bool {
	return b == '*'
}

func (p *boldDelimiterProcessor) CanOpenCloser(opener, closer *parser.Delimiter) bool {
	return opener.Char == closer.Char
}

func (p *boldDelimiterProcessor) OnMatch(consumes int) ast.Node {
	return ast.NewEmphasis(2)
}

var defaultBoldDelimiterProcessor = &boldDelimiterProcessor{}

type boldParser struct{}

func (s *boldParser) Trigger() []byte {
	return []byte{'*'}
}

func (s *boldParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	before := block.PrecendingCharacter()
	line, segment := block.PeekLine()
	node := parser.ScanDelimiter(line, before, 1, defaultBoldDelimiterProcessor)
	if node == nil || node.OriginalLength > 1 || before == '*' {
		return nil
	}
	node.Segment = segment.WithStop(segment.Start + node.OriginalLength)
	block.Advance(node.OriginalLength)
	pc.PushDelimiter(node)
	return node
}
