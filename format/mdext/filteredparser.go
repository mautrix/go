// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mdext

import (
	"reflect"

	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/util"
)

func filterParsers(list []util.PrioritizedValue, forbidden map[reflect.Type]struct{}) []util.PrioritizedValue {
	n := 0
	for _, item := range list {
		if _, isForbidden := forbidden[reflect.TypeOf(item.Value)]; isForbidden {
			continue
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
	forbiddenTypes := make(map[reflect.Type]struct{}, len(features))
	for _, feature := range features {
		forbiddenTypes[reflect.TypeOf(feature)] = struct{}{}
	}
	filteredBlockParsers := filterParsers(parser.DefaultBlockParsers(), forbiddenTypes)
	filteredInlineParsers := filterParsers(parser.DefaultInlineParsers(), forbiddenTypes)
	filteredParagraphTransformers := filterParsers(parser.DefaultParagraphTransformers(), forbiddenTypes)
	return parser.NewParser(
		parser.WithBlockParsers(filteredBlockParsers...),
		parser.WithInlineParsers(filteredInlineParsers...),
		parser.WithParagraphTransformers(filteredParagraphTransformers...),
	)
}
