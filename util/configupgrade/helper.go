// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package configupgrade

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type YAMLMap map[string]YAMLNode
type YAMLList []YAMLNode

type YAMLNode struct {
	*yaml.Node
	Map  YAMLMap
	List YAMLList
	Key  *yaml.Node
}

type YAMLType uint32

const (
	Null YAMLType = 1 << iota
	Bool
	Str
	Int
	Float
	Timestamp
	List
	Map
	Binary
)

func (t YAMLType) String() string {
	switch t {
	case Null:
		return NullTag
	case Bool:
		return BoolTag
	case Str:
		return StrTag
	case Int:
		return IntTag
	case Float:
		return FloatTag
	case Timestamp:
		return TimestampTag
	case List:
		return SeqTag
	case Map:
		return MapTag
	case Binary:
		return BinaryTag
	default:
		panic(fmt.Errorf("can't convert type %d to string", t))
	}
}

func tagToType(tag string) YAMLType {
	switch tag {
	case NullTag:
		return Null
	case BoolTag:
		return Bool
	case StrTag:
		return Str
	case IntTag:
		return Int
	case FloatTag:
		return Float
	case TimestampTag:
		return Timestamp
	case SeqTag:
		return List
	case MapTag:
		return Map
	case BinaryTag:
		return Binary
	default:
		return 0
	}
}

const (
	NullTag      = "!!null"
	BoolTag      = "!!bool"
	StrTag       = "!!str"
	IntTag       = "!!int"
	FloatTag     = "!!float"
	TimestampTag = "!!timestamp"
	SeqTag       = "!!seq"
	MapTag       = "!!map"
	BinaryTag    = "!!binary"
)

func fromNode(node, key *yaml.Node) YAMLNode {
	switch node.Kind {
	case yaml.DocumentNode:
		return fromNode(node.Content[0], nil)
	case yaml.AliasNode:
		return fromNode(node.Alias, nil)
	case yaml.MappingNode:
		return YAMLNode{
			Node: node,
			Map:  parseYAMLMap(node),
			Key:  key,
		}
	case yaml.SequenceNode:
		return YAMLNode{
			Node: node,
			List: parseYAMLList(node),
		}
	default:
		return YAMLNode{Node: node, Key: key}
	}
}

func (yn *YAMLNode) toNode() *yaml.Node {
	yn.UpdateContent()
	return yn.Node
}

func (yn *YAMLNode) UpdateContent() {
	switch {
	case yn.Map != nil && yn.Node.Kind == yaml.MappingNode:
		yn.Content = yn.Map.toNodes()
	case yn.List != nil && yn.Node.Kind == yaml.SequenceNode:
		yn.Content = yn.List.toNodes()
	}
}

func parseYAMLList(node *yaml.Node) YAMLList {
	data := make(YAMLList, len(node.Content))
	for i, item := range node.Content {
		data[i] = fromNode(item, nil)
	}
	return data
}

func (yl YAMLList) toNodes() []*yaml.Node {
	nodes := make([]*yaml.Node, len(yl))
	for i, item := range yl {
		nodes[i] = item.toNode()
	}
	return nodes
}

func parseYAMLMap(node *yaml.Node) YAMLMap {
	if len(node.Content)%2 != 0 {
		panic(fmt.Errorf("uneven number of items in YAML map (%d)", len(node.Content)))
	}
	data := make(YAMLMap, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		if key.Kind == yaml.ScalarNode {
			data[key.Value] = fromNode(value, key)
		}
	}
	return data
}

func (ym YAMLMap) toNodes() []*yaml.Node {
	nodes := make([]*yaml.Node, len(ym)*2)
	i := 0
	for key, value := range ym {
		nodes[i] = makeStringNode(key)
		nodes[i+1] = value.toNode()
		i += 2
	}
	return nodes
}

func makeStringNode(val string) *yaml.Node {
	var node yaml.Node
	node.SetString(val)
	return &node
}

func StringNode(val string) YAMLNode {
	return YAMLNode{Node: makeStringNode(val)}
}

type Helper struct {
	Base   YAMLNode
	Config YAMLNode
}

func NewHelper(base, cfg *yaml.Node) *Helper {
	return &Helper{
		Base:   fromNode(base, nil),
		Config: fromNode(cfg, nil),
	}
}

func (helper *Helper) AddSpaceBeforeComment(path ...string) {
	node := helper.GetBaseNode(path...)
	if node == nil || node.Key == nil {
		panic(fmt.Errorf("didn't find key at %+v", path))
	}
	node.Key.HeadComment = "\n" + node.Key.HeadComment
}

func (helper *Helper) Copy(allowedTypes YAMLType, path ...string) {
	base, cfg := helper.Base, helper.Config
	var ok bool
	for _, item := range path {
		cfg, ok = cfg.Map[item]
		if !ok {
			return
		}
		base, ok = base.Map[item]
		if !ok {
			_, _ = fmt.Fprintf(os.Stderr, "Ignoring config field %s which is missing in base config\n", strings.Join(path, "->"))
			return
		}
	}
	if allowedTypes&tagToType(cfg.Tag) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Ignoring incorrect config field type %s at %s\n", cfg.Tag, strings.Join(path, "->"))
		return
	}
	base.Tag = cfg.Tag
	base.Style = cfg.Style
	switch base.Kind {
	case yaml.ScalarNode:
		base.Value = cfg.Value
	case yaml.SequenceNode, yaml.MappingNode:
		base.Content = cfg.Content
	}
}

func getNode(cfg YAMLNode, path []string) *YAMLNode {
	var ok bool
	for _, item := range path {
		cfg, ok = cfg.Map[item]
		if !ok {
			return nil
		}
	}
	return &cfg
}

func (helper *Helper) GetNode(path ...string) *YAMLNode {
	return getNode(helper.Config, path)
}

func (helper *Helper) GetBaseNode(path ...string) *YAMLNode {
	return getNode(helper.Base, path)
}

func (helper *Helper) Get(tag YAMLType, path ...string) (string, bool) {
	node := helper.GetNode(path...)
	if node == nil || node.Kind != yaml.ScalarNode || tag&tagToType(node.Tag) == 0 {
		return "", false
	}
	return node.Value, true
}

func (helper *Helper) GetBase(path ...string) string {
	return helper.GetBaseNode(path...).Value
}

func (helper *Helper) Set(tag YAMLType, value string, path ...string) {
	base := helper.Base
	for _, item := range path {
		base = base.Map[item]
	}
	base.Tag = tag.String()
	base.Value = value
}

func (helper *Helper) SetMap(value YAMLMap, path ...string) {
	base := helper.Base
	for _, item := range path {
		base = base.Map[item]
	}
	if base.Tag != MapTag || base.Kind != yaml.MappingNode {
		panic(fmt.Errorf("invalid target for SetMap(%+v): tag:%s, kind:%d", path, base.Tag, base.Kind))
	}
	base.Content = value.toNodes()
}
