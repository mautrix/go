// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mdext

import (
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/util"
)

func filterParsers(list []util.PrioritizedValue, forbidden ...any) []util.PrioritizedValue {
	n := 0
itemLoop:
	for _, item := range list {
		for _, forbiddenItem := range forbidden {
			if item.Value == forbiddenItem {
				continue itemLoop
			}
		}
		list[n] = item
		n++
	}
	return list[:n]
}

// ParserWithoutFeatures returns a Goldmark parser with the provided default features removed.
//
// e.g. to disable lists, use
//
//	markdown := goldmark.New(goldmark.WithParser(
//		mdext.ParserWithoutFeatures(goldmark.NewListParser(), goldmark.NewListItemParser())
//	))
func ParserWithoutFeatures(features ...any) parser.Parser {
	filteredBlockParsers := filterParsers(parser.DefaultBlockParsers(), features...)
	filteredInlineParsers := filterParsers(parser.DefaultInlineParsers(), features...)
	filteredParagraphTransformers := filterParsers(parser.DefaultParagraphTransformers(), features...)
	return parser.NewParser(
		parser.WithBlockParsers(filteredBlockParsers...),
		parser.WithInlineParsers(filteredInlineParsers...),
		parser.WithParagraphTransformers(filteredParagraphTransformers...),
	)
}
