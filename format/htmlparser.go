// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package format

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"maunium.net/go/mautrix/id"
)

type Context map[string]interface{}
type TextConverter func(string, Context) string
type SpoilerConverter func(text, reason string, ctx Context) string
type LinkConverter func(text, href string, ctx Context) string
type ColorConverter func(text, fg, bg string, ctx Context) string
type CodeBlockConverter func(code, language string, ctx Context) string
type PillConverter func(displayname, mxid, eventID string, ctx Context) string

func DefaultPillConverter(displayname, mxid, eventID string, _ Context) string {
	switch {
	case len(mxid) == 0, mxid[0] == '@':
		// User link, always just show the displayname
		return displayname
	case len(eventID) > 0:
		// Event ID link, always just show the link
		return fmt.Sprintf("https://matrix.to/#/%s/%s", mxid, eventID)
	case mxid[0] == '!' && displayname == mxid:
		// Room ID link with no separate display text, just show the link
		return fmt.Sprintf("https://matrix.to/#/%s", mxid)
	case mxid[0] == '#':
		// Room alias link, just show the alias
		return mxid
	default:
		// Other link (e.g. room ID link with display text), show text and link
		return fmt.Sprintf("%s (https://matrix.to/#/%s)", displayname, mxid)
	}
}

// HTMLParser is a somewhat customizable Matrix HTML parser.
type HTMLParser struct {
	PillConverter           PillConverter
	TabsToSpaces            int
	Newline                 string
	HorizontalLine          string
	BoldConverter           TextConverter
	ItalicConverter         TextConverter
	StrikethroughConverter  TextConverter
	UnderlineConverter      TextConverter
	LinkConverter           LinkConverter
	SpoilerConverter        SpoilerConverter
	ColorConverter          ColorConverter
	MonospaceBlockConverter CodeBlockConverter
	MonospaceConverter      TextConverter
	TextConverter           TextConverter
}

// TaggedString is a string that also contains a HTML tag.
type TaggedString struct {
	string
	tag string
}

func (parser *HTMLParser) maybeGetAttribute(node *html.Node, attribute string) (string, bool) {
	for _, attr := range node.Attr {
		if attr.Key == attribute {
			return attr.Val, true
		}
	}
	return "", false
}

func (parser *HTMLParser) getAttribute(node *html.Node, attribute string) string {
	val, _ := parser.maybeGetAttribute(node, attribute)
	return val
}

// Digits counts the number of digits (and the sign, if negative) in an integer.
func Digits(num int) int {
	if num == 0 {
		return 1
	} else if num < 0 {
		return Digits(-num) + 1
	}
	return int(math.Floor(math.Log10(float64(num))) + 1)
}

func (parser *HTMLParser) listToString(node *html.Node, stripLinebreak bool, ctx Context) string {
	ordered := node.Data == "ol"
	taggedChildren := parser.nodeToTaggedStrings(node.FirstChild, stripLinebreak, ctx)
	counter := 1
	indentLength := 0
	if ordered {
		start := parser.getAttribute(node, "start")
		if len(start) > 0 {
			counter, _ = strconv.Atoi(start)
		}

		longestIndex := (counter - 1) + len(taggedChildren)
		indentLength = Digits(longestIndex)
	}
	indent := strings.Repeat(" ", indentLength+2)
	var children []string
	for _, child := range taggedChildren {
		if child.tag != "li" {
			continue
		}
		var prefix string
		// TODO make bullets and numbering configurable
		if ordered {
			indexPadding := indentLength - Digits(counter)
			if indexPadding < 0 {
				// This will happen on negative start indexes where longestIndex is usually wrong, otherwise shouldn't happen
				indexPadding = 0
			}
			prefix = fmt.Sprintf("%d. %s", counter, strings.Repeat(" ", indexPadding))
		} else {
			prefix = "* "
		}
		str := prefix + child.string
		counter++
		parts := strings.Split(str, "\n")
		for i, part := range parts[1:] {
			parts[i+1] = indent + part
		}
		str = strings.Join(parts, "\n")
		children = append(children, str)
	}
	return strings.Join(children, "\n")
}

func (parser *HTMLParser) basicFormatToString(node *html.Node, stripLinebreak bool, ctx Context) string {
	str := parser.nodeToTagAwareString(node.FirstChild, stripLinebreak, ctx)
	switch node.Data {
	case "b", "strong":
		if parser.BoldConverter != nil {
			return parser.BoldConverter(str, ctx)
		}
		return fmt.Sprintf("**%s**", str)
	case "i", "em":
		if parser.ItalicConverter != nil {
			return parser.ItalicConverter(str, ctx)
		}
		return fmt.Sprintf("_%s_", str)
	case "s", "del", "strike":
		if parser.StrikethroughConverter != nil {
			return parser.StrikethroughConverter(str, ctx)
		}
		return fmt.Sprintf("~~%s~~", str)
	case "u", "ins":
		if parser.UnderlineConverter != nil {
			return parser.UnderlineConverter(str, ctx)
		}
	case "tt", "code":
		if parser.MonospaceConverter != nil {
			return parser.MonospaceConverter(str, ctx)
		}
		return fmt.Sprintf("`%s`", str)
	}
	return str
}

func (parser *HTMLParser) spanToString(node *html.Node, stripLinebreak bool, ctx Context) string {
	str := parser.nodeToTagAwareString(node.FirstChild, stripLinebreak, ctx)
	if node.Data == "span" {
		reason, isSpoiler := parser.maybeGetAttribute(node, "data-mx-spoiler")
		if isSpoiler {
			if parser.SpoilerConverter != nil {
				str = parser.SpoilerConverter(str, reason, ctx)
			} else if len(reason) > 0 {
				str = fmt.Sprintf("||%s|%s||", reason, str)
			} else {
				str = fmt.Sprintf("||%s||", str)
			}
		}
	}
	if parser.ColorConverter != nil {
		fg := parser.getAttribute(node, "data-mx-color")
		if len(fg) == 0 && node.Data == "font" {
			fg = parser.getAttribute(node, "color")
		}
		bg := parser.getAttribute(node, "data-mx-bg-color")
		if len(bg) > 0 || len(fg) > 0 {
			str = parser.ColorConverter(str, fg, bg, ctx)
		}
	}
	return str
}

func (parser *HTMLParser) headerToString(node *html.Node, stripLinebreak bool, ctx Context) string {
	children := parser.nodeToStrings(node.FirstChild, stripLinebreak, ctx)
	length := int(node.Data[1] - '0')
	prefix := strings.Repeat("#", length) + " "
	return prefix + strings.Join(children, "")
}

func (parser *HTMLParser) blockquoteToString(node *html.Node, stripLinebreak bool, ctx Context) string {
	str := parser.nodeToTagAwareString(node.FirstChild, stripLinebreak, ctx)
	childrenArr := strings.Split(strings.TrimSpace(str), "\n")
	// TODO make blockquote prefix configurable
	for index, child := range childrenArr {
		childrenArr[index] = "> " + child
	}
	return strings.Join(childrenArr, "\n")
}

func (parser *HTMLParser) linkToString(node *html.Node, stripLinebreak bool, ctx Context) string {
	str := parser.nodeToTagAwareString(node.FirstChild, stripLinebreak, ctx)
	href := parser.getAttribute(node, "href")
	if len(href) == 0 {
		return str
	}
	if parser.PillConverter != nil {
		parsedMatrix, err := id.ParseMatrixURIOrMatrixToURL(href)
		if err == nil && parsedMatrix != nil {
			return parser.PillConverter(str, parsedMatrix.PrimaryIdentifier(), parsedMatrix.SecondaryIdentifier(), ctx)
		}
	}
	if parser.LinkConverter != nil {
		return parser.LinkConverter(str, href, ctx)
	} else if str == href {
		return str
	}
	return fmt.Sprintf("%s (%s)", str, href)
}

func (parser *HTMLParser) tagToString(node *html.Node, stripLinebreak bool, ctx Context) string {
	switch node.Data {
	case "blockquote":
		return parser.blockquoteToString(node, stripLinebreak, ctx)
	case "ol", "ul":
		return parser.listToString(node, stripLinebreak, ctx)
	case "h1", "h2", "h3", "h4", "h5", "h6":
		return parser.headerToString(node, stripLinebreak, ctx)
	case "br":
		return parser.Newline
	case "b", "strong", "i", "em", "s", "strike", "del", "u", "ins", "tt", "code":
		return parser.basicFormatToString(node, stripLinebreak, ctx)
	case "span", "font":
		return parser.spanToString(node, stripLinebreak, ctx)
	case "a":
		return parser.linkToString(node, stripLinebreak, ctx)
	case "p":
		return parser.nodeToTagAwareString(node.FirstChild, stripLinebreak, ctx)
	case "hr":
		return parser.HorizontalLine
	case "pre":
		var preStr, language string
		if node.FirstChild != nil && node.FirstChild.Type == html.ElementNode && node.FirstChild.Data == "code" {
			class := parser.getAttribute(node.FirstChild, "class")
			if strings.HasPrefix(class, "language-") {
				language = class[len("language-"):]
			}
			preStr = parser.nodeToString(node.FirstChild.FirstChild, false, ctx)
		} else {
			preStr = parser.nodeToString(node.FirstChild, false, ctx)
		}
		if parser.MonospaceBlockConverter != nil {
			return parser.MonospaceBlockConverter(preStr, language, ctx)
		}
		if len(preStr) == 0 || preStr[len(preStr)-1] != '\n' {
			preStr += "\n"
		}
		return fmt.Sprintf("```%s\n%s```", language, preStr)
	default:
		return parser.nodeToTagAwareString(node.FirstChild, stripLinebreak, ctx)
	}
}

func (parser *HTMLParser) singleNodeToString(node *html.Node, stripLinebreak bool, ctx Context) TaggedString {
	switch node.Type {
	case html.TextNode:
		if stripLinebreak {
			node.Data = strings.Replace(node.Data, "\n", "", -1)
		}
		if parser.TextConverter != nil {
			node.Data = parser.TextConverter(node.Data, ctx)
		}
		return TaggedString{node.Data, "text"}
	case html.ElementNode:
		return TaggedString{parser.tagToString(node, stripLinebreak, ctx), node.Data}
	case html.DocumentNode:
		return TaggedString{parser.nodeToTagAwareString(node.FirstChild, stripLinebreak, ctx), "html"}
	default:
		return TaggedString{"", "unknown"}
	}
}

func (parser *HTMLParser) nodeToTaggedStrings(node *html.Node, stripLinebreak bool, ctx Context) (strs []TaggedString) {
	for ; node != nil; node = node.NextSibling {
		strs = append(strs, parser.singleNodeToString(node, stripLinebreak, ctx))
	}
	return
}

var BlockTags = []string{"p", "h1", "h2", "h3", "h4", "h5", "h6", "ol", "ul", "pre", "blockquote", "div", "hr", "table"}

func (parser *HTMLParser) isBlockTag(tag string) bool {
	for _, blockTag := range BlockTags {
		if tag == blockTag {
			return true
		}
	}
	return false
}

func (parser *HTMLParser) nodeToTagAwareString(node *html.Node, stripLinebreak bool, ctx Context) string {
	strs := parser.nodeToTaggedStrings(node, stripLinebreak, ctx)
	var output strings.Builder
	for _, str := range strs {
		tstr := str.string
		if parser.isBlockTag(str.tag) {
			tstr = fmt.Sprintf("\n%s\n", tstr)
		}
		output.WriteString(tstr)
	}
	return strings.TrimSpace(output.String())
}

func (parser *HTMLParser) nodeToStrings(node *html.Node, stripLinebreak bool, ctx Context) (strs []string) {
	for ; node != nil; node = node.NextSibling {
		strs = append(strs, parser.singleNodeToString(node, stripLinebreak, ctx).string)
	}
	return
}

func (parser *HTMLParser) nodeToString(node *html.Node, stripLinebreak bool, ctx Context) string {
	return strings.Join(parser.nodeToStrings(node, stripLinebreak, ctx), "")
}

// Parse converts Matrix HTML into text using the settings in this parser.
func (parser *HTMLParser) Parse(htmlData string, ctx Context) string {
	if parser.TabsToSpaces >= 0 {
		htmlData = strings.Replace(htmlData, "\t", strings.Repeat(" ", parser.TabsToSpaces), -1)
	}
	node, _ := html.Parse(strings.NewReader(htmlData))
	return parser.nodeToTagAwareString(node, true, ctx)
}

// HTMLToText converts Matrix HTML into text with the default settings.
func HTMLToText(html string) string {
	return (&HTMLParser{
		TabsToSpaces:   4,
		Newline:        "\n",
		HorizontalLine: "\n---\n",
		PillConverter:  DefaultPillConverter,
	}).Parse(html, make(Context))
}

// HTMLToMarkdown converts Matrix HTML into markdown with the default settings.
//
// Currently, the only difference to HTMLToText is how links are formatted.
func HTMLToMarkdown(html string) string {
	return (&HTMLParser{
		TabsToSpaces:   4,
		Newline:        "\n",
		HorizontalLine: "\n---\n",
		PillConverter:  DefaultPillConverter,
		LinkConverter: func(text, href string, ctx Context) string {
			if text == href {
				return text
			}
			return fmt.Sprintf("[%s](%s)", text, href)
		},
	}).Parse(html, make(Context))
}
