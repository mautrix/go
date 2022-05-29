// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mdext

import (
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/util"
)

type extEscapeHTML struct{}
type escapingHTMLRenderer struct{}

// EscapeHTML is an extension that escapes HTML in the input markdown instead of passing it through as-is.
var EscapeHTML = &extEscapeHTML{}
var defaultEHR = &escapingHTMLRenderer{}

func (eeh *extEscapeHTML) Extend(m goldmark.Markdown) {
	m.Renderer().AddOptions(renderer.WithNodeRenderers(util.Prioritized(defaultEHR, 0)))
}

func (ehr *escapingHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindHTMLBlock, ehr.renderHTMLBlock)
	reg.Register(ast.KindRawHTML, ehr.renderRawHTML)
}

func (ehr *escapingHTMLRenderer) renderRawHTML(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkSkipChildren, nil
	}
	n := node.(*ast.RawHTML)
	l := n.Segments.Len()
	for i := 0; i < l; i++ {
		segment := n.Segments.At(i)
		html.DefaultWriter.RawWrite(w, segment.Value(source))
	}
	return ast.WalkSkipChildren, nil
}

func (ehr *escapingHTMLRenderer) renderHTMLBlock(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	n := node.(*ast.HTMLBlock)
	if entering {
		l := n.Lines().Len()
		for i := 0; i < l; i++ {
			line := n.Lines().At(i)
			html.DefaultWriter.RawWrite(w, line.Value(source))
		}
	} else {
		if n.HasClosure() {
			closure := n.ClosureLine
			html.DefaultWriter.RawWrite(w, closure.Value(source))
		}
	}
	return ast.WalkContinue, nil
}
