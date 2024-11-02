// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mdext

import (
	"bytes"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/util"
)

type extCustomEmoji struct{}
type customEmojiRenderer struct {
	funcs functionCapturer
}

// CustomEmoji is an extension that converts certain markdown images into Matrix custom emojis.
var CustomEmoji = &extCustomEmoji{}

type functionCapturer struct {
	renderImage  renderer.NodeRendererFunc
	renderText   renderer.NodeRendererFunc
	renderString renderer.NodeRendererFunc
}

func (fc *functionCapturer) Register(kind ast.NodeKind, rendererFunc renderer.NodeRendererFunc) {
	switch kind {
	case ast.KindImage:
		fc.renderImage = rendererFunc
	case ast.KindText:
		fc.renderText = rendererFunc
	case ast.KindString:
		fc.renderString = rendererFunc
	}
}

var (
	_ renderer.NodeRendererFuncRegisterer = (*functionCapturer)(nil)
	_ renderer.Option                     = (*functionCapturer)(nil)
)

func (fc *functionCapturer) SetConfig(cfg *renderer.Config) {
	cfg.NodeRenderers[0].Value.(renderer.NodeRenderer).RegisterFuncs(fc)
}

func (eeh *extCustomEmoji) Extend(m goldmark.Markdown) {
	var fc functionCapturer
	m.Renderer().AddOptions(&fc)
	m.Renderer().AddOptions(renderer.WithNodeRenderers(util.Prioritized(&customEmojiRenderer{fc}, 0)))
}

func (cer *customEmojiRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindImage, cer.renderImage)
}

var emojiPrefix = []byte("Emoji: ")
var mxcPrefix = []byte("mxc://")

func (cer *customEmojiRenderer) renderImage(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	n, ok := node.(*ast.Image)
	if ok && entering && bytes.HasPrefix(n.Title, emojiPrefix) && bytes.HasPrefix(n.Destination, mxcPrefix) {
		n.Title = bytes.TrimPrefix(n.Title, emojiPrefix)
		n.SetAttributeString("data-mx-emoticon", nil)
		n.SetAttributeString("height", "32")
	}
	return cer.funcs.renderImage(w, source, node, entering)
}
