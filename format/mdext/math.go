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
	"regexp"
	"strings"
	"unicode"

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
	value []byte
}

func (n *astMath) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, nil, nil)
}

func (n *astMath) Kind() ast.NodeKind {
	return astKindMath
}

type astMathBlock struct {
	ast.BaseBlock
}

func (n *astMathBlock) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, nil, nil)
}

func (n *astMathBlock) Kind() ast.NodeKind {
	return astKindMath
}

type inlineMathParser struct{}

var defaultInlineMathParser = &inlineMathParser{}

func NewInlineMathParser() parser.InlineParser {
	return defaultInlineMathParser
}

const mathDelimiter = '$'

func (s *inlineMathParser) Trigger() []byte {
	return []byte{mathDelimiter}
}

// This ignores lines where there's no space after the closing $ to avoid false positives
var latexInlineRegexp = regexp.MustCompile(`^(\$[^$]*\$)(?:$|\s)`)

func (s *inlineMathParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	before := block.PrecendingCharacter()
	// Ignore lines where the opening $ comes after a letter or number to avoid false positives
	if unicode.IsLetter(before) || unicode.IsNumber(before) {
		return nil
	}
	line, segment := block.PeekLine()
	idx := latexInlineRegexp.FindSubmatchIndex(line)
	if idx == nil {
		return nil
	}
	block.Advance(idx[3])
	return &astMath{
		value: block.Value(text.NewSegment(segment.Start+1, segment.Start+idx[3]-1)),
	}
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
	line, _ := reader.PeekLine()
	pos := pc.BlockOffset()
	if pos < 0 || (line[pos] != mathDelimiter) {
		return nil, parser.NoChildren
	}
	findent := pos
	i := pos
	for ; i < len(line) && line[i] == mathDelimiter; i++ {
	}
	oFenceLength := i - pos
	if oFenceLength < 2 {
		return nil, parser.NoChildren
	}
	if i < len(line)-1 {
		rest := line[i:]
		left := util.TrimLeftSpaceLength(rest)
		right := util.TrimRightSpaceLength(rest)
		if left < len(rest)-right {
			value := rest[left : len(rest)-right]
			if bytes.IndexByte(value, mathDelimiter) > -1 {
				return nil, parser.NoChildren
			}
		}
	}
	node := &astMathBlock{}
	pc.Set(mathBlockInfoKey, &mathBlockData{findent, oFenceLength, node})
	return node, parser.NoChildren

}

func (b *blockMathParser) Continue(node ast.Node, reader text.Reader, pc parser.Context) parser.State {
	line, segment := reader.PeekLine()
	fdata := pc.Get(mathBlockInfoKey).(*mathBlockData)

	w, pos := util.IndentWidth(line, reader.LineOffset())
	if w < 4 {
		i := pos
		for ; i < len(line) && line[i] == mathDelimiter; i++ {
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
		var tex string
		switch typed := n.(type) {
		case *astMathBlock:
			tag = "div"
			tex = string(n.Lines().Value(source))
		case *astMath:
			tex = string(typed.value)
		}
		tex = stdhtml.EscapeString(strings.TrimSpace(tex))
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
