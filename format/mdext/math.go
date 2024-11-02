// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mdext

import (
	"bytes"
	"fmt"
	stdhtml "html"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

var astKindMath = ast.NewNodeKind("Math")

type astMath struct {
	ast.BaseInline
	block bool
}

func (n *astMath) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, nil, nil)
}

func (n *astMath) Kind() ast.NodeKind {
	return astKindMath
}

type astMathBlock struct {
	ast.BaseBlock
	info *ast.Text
}

func (n *astMathBlock) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, nil, nil)
}

func (n *astMathBlock) Kind() ast.NodeKind {
	return astKindMath
}

type mathDelimiterProcessor struct{}

var defaultMathDelimiterProcessor = &mathDelimiterProcessor{}

func (p *mathDelimiterProcessor) IsDelimiter(b byte) bool {
	return b == '$'
}

func (p *mathDelimiterProcessor) CanOpenCloser(opener, closer *parser.Delimiter) bool {
	return opener.Char == closer.Char
}

func (p *mathDelimiterProcessor) OnMatch(consumes int) ast.Node {
	return &astMath{block: consumes > 1}
}

type inlineMathParser struct{}

var defaultInlineMathParser = &inlineMathParser{}

func NewInlineMathParser() parser.InlineParser {
	return defaultInlineMathParser
}

func (s *inlineMathParser) Trigger() []byte {
	return []byte{'$'}
}

func (s *inlineMathParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	before := block.PrecendingCharacter()
	line, segment := block.PeekLine()
	node := parser.ScanDelimiter(line, before, 1, defaultMathDelimiterProcessor)
	if node == nil {
		return nil
	}
	node.Segment = segment.WithStop(segment.Start + node.OriginalLength)
	block.Advance(node.OriginalLength)
	pc.PushDelimiter(node)
	return node
}

func (s *inlineMathParser) CloseBlock(parent ast.Node, pc parser.Context) {
	// nothing to do
}

type blockMathParser struct{}

var defaultBlockMathParser = &blockMathParser{}

func NewBlockMathParser() parser.BlockParser {
	return defaultBlockMathParser
}

var mathBlockInfoKey = parser.NewContextKey()

type mathBlockData struct {
	indent int
	length int
	node   ast.Node
}

func (b *blockMathParser) Trigger() []byte {
	return []byte{'$'}
}

func (b *blockMathParser) Open(parent ast.Node, reader text.Reader, pc parser.Context) (ast.Node, parser.State) {
	const fenceChar = '$'
	line, segment := reader.PeekLine()
	pos := pc.BlockOffset()
	if pos < 0 || (line[pos] != fenceChar) {
		return nil, parser.NoChildren
	}
	findent := pos
	i := pos
	for ; i < len(line) && line[i] == fenceChar; i++ {
	}
	oFenceLength := i - pos
	if oFenceLength < 2 {
		return nil, parser.NoChildren
	}
	var info *ast.Text
	if i < len(line)-1 {
		rest := line[i:]
		left := util.TrimLeftSpaceLength(rest)
		right := util.TrimRightSpaceLength(rest)
		if left < len(rest)-right {
			infoStart, infoStop := segment.Start-segment.Padding+i+left, segment.Stop-right
			value := rest[left : len(rest)-right]
			if bytes.IndexByte(value, fenceChar) > -1 {
				return nil, parser.NoChildren
			} else if infoStart != infoStop {
				info = ast.NewTextSegment(text.NewSegment(infoStart, infoStop))
			}
		}
	}
	node := &astMathBlock{info: info}
	pc.Set(mathBlockInfoKey, &mathBlockData{findent, oFenceLength, node})
	return node, parser.NoChildren

}

func (b *blockMathParser) Continue(node ast.Node, reader text.Reader, pc parser.Context) parser.State {
	const fenceChar = '$'
	line, segment := reader.PeekLine()
	fdata := pc.Get(mathBlockInfoKey).(*mathBlockData)

	w, pos := util.IndentWidth(line, reader.LineOffset())
	if w < 4 {
		i := pos
		for ; i < len(line) && line[i] == fenceChar; i++ {
		}
		length := i - pos
		if length >= fdata.length && util.IsBlank(line[i:]) {
			newline := 1
			if line[len(line)-1] != '\n' {
				newline = 0
			}
			reader.Advance(segment.Stop - segment.Start - newline + segment.Padding)
			return parser.Close
		}
	}
	pos, padding := util.IndentPositionPadding(line, reader.LineOffset(), segment.Padding, fdata.indent)
	if pos < 0 {
		pos = util.FirstNonSpacePosition(line)
		if pos < 0 {
			pos = 0
		}
		padding = 0
	}
	seg := text.NewSegmentPadding(segment.Start+pos, segment.Stop, padding)
	seg.ForceNewline = true // EOF as newline
	node.Lines().Append(seg)
	reader.AdvanceAndSetPadding(segment.Stop-segment.Start-pos-1, padding)
	return parser.Continue | parser.NoChildren
}

func (b *blockMathParser) Close(node ast.Node, reader text.Reader, pc parser.Context) {
	fdata := pc.Get(mathBlockInfoKey).(*mathBlockData)
	if fdata.node == node {
		pc.Set(mathBlockInfoKey, nil)
	}
}

func (b *blockMathParser) CanInterruptParagraph() bool {
	return true
}

func (b *blockMathParser) CanAcceptIndentedLine() bool {
	return false
}

type mathHTMLRenderer struct {
	html.Config
}

func NewMathHTMLRenderer(opts ...html.Option) renderer.NodeRenderer {
	r := &mathHTMLRenderer{
		Config: html.NewConfig(),
	}
	for _, opt := range opts {
		opt.SetHTMLOption(&r.Config)
	}
	return r
}

func (r *mathHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(astKindMath, r.renderMath)
}

func (r *mathHTMLRenderer) renderMath(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		tag := "span"
		switch typed := n.(type) {
		case *astMathBlock:
			tag = "div"
		case *astMath:
			if typed.block {
				tag = "div"
			}
		}
		tex := stdhtml.EscapeString(string(n.Text(source)))
		_, _ = fmt.Fprintf(w, `<%s data-mx-maths="%s"><code>%s</code></%s>`, tag, tex, strings.ReplaceAll(tex, "\n", "<br>"), tag)
	}
	return ast.WalkSkipChildren, nil
}

type math struct{}

// Math is an extension that allow you to use math like '$$text$$'.
var Math = &math{}

func (e *math) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithInlineParsers(
		util.Prioritized(NewInlineMathParser(), 500),
	), parser.WithBlockParsers(
		util.Prioritized(NewBlockMathParser(), 850),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(NewMathHTMLRenderer(), 500),
	))
}
