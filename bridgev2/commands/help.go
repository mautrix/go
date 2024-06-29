// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"fmt"
	"sort"
	"strings"
)

type HelpfulHandler interface {
	CommandHandler
	GetHelp() HelpMeta
	ShowInHelp(*Event) bool
}

type HelpSection struct {
	Name  string
	Order int
}

var (
	// Deprecated: this should be used as a placeholder that needs to be fixed
	HelpSectionUnclassified = HelpSection{"Unclassified", -1}

	HelpSectionGeneral = HelpSection{"General", 0}
	HelpSectionAuth    = HelpSection{"Authentication", 10}
	HelpSectionChats   = HelpSection{"Starting and managing chats", 20}
	HelpSectionAdmin   = HelpSection{"Administration", 50}
)

type HelpMeta struct {
	Command     string
	Section     HelpSection
	Description string
	Args        string
}

func (hm *HelpMeta) String() string {
	if len(hm.Args) == 0 {
		return fmt.Sprintf("**%s** - %s", hm.Command, hm.Description)
	}
	return fmt.Sprintf("**%s** %s - %s", hm.Command, hm.Args, hm.Description)
}

type helpSectionList []HelpSection

func (h helpSectionList) Len() int {
	return len(h)
}

func (h helpSectionList) Less(i, j int) bool {
	return h[i].Order < h[j].Order
}

func (h helpSectionList) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

type helpMetaList []HelpMeta

func (h helpMetaList) Len() int {
	return len(h)
}

func (h helpMetaList) Less(i, j int) bool {
	return h[i].Command < h[j].Command
}

func (h helpMetaList) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

var _ sort.Interface = (helpSectionList)(nil)
var _ sort.Interface = (helpMetaList)(nil)

func FormatHelp(ce *Event) string {
	sections := make(map[HelpSection]helpMetaList)
	for _, handler := range ce.Processor.handlers {
		helpfulHandler, ok := handler.(HelpfulHandler)
		if !ok || !helpfulHandler.ShowInHelp(ce) {
			continue
		}
		help := helpfulHandler.GetHelp()
		if help.Description == "" {
			continue
		}
		sections[help.Section] = append(sections[help.Section], help)
	}

	sortedSections := make(helpSectionList, 0, len(sections))
	for section := range sections {
		sortedSections = append(sortedSections, section)
	}
	sort.Sort(sortedSections)

	var output strings.Builder
	output.Grow(10240)

	var prefixMsg string
	if ce.RoomID == ce.User.ManagementRoom {
		prefixMsg = "This is your management room: prefixing commands with `%s` is not required."
	} else if ce.Portal != nil {
		prefixMsg = "**This is a portal room**: you must always prefix commands with `%s`. Management commands will not be bridged."
	} else {
		prefixMsg = "This is not your management room: prefixing commands with `%s` is required."
	}
	_, _ = fmt.Fprintf(&output, prefixMsg, ce.Bridge.Config.CommandPrefix)
	output.WriteByte('\n')
	output.WriteString("Parameters in [square brackets] are optional, while parameters in <angle brackets> are required.")
	output.WriteByte('\n')
	output.WriteByte('\n')

	for _, section := range sortedSections {
		output.WriteString("#### ")
		output.WriteString(section.Name)
		output.WriteByte('\n')
		sort.Sort(sections[section])
		for _, command := range sections[section] {
			output.WriteString(command.String())
			output.WriteByte('\n')
		}
		output.WriteByte('\n')
	}
	return output.String()
}

var CommandHelp = &FullHandler{
	Func: func(ce *Event) {
		ce.Reply(FormatHelp(ce))
	},
	Name: "help",
	Help: HelpMeta{
		Section:     HelpSectionGeneral,
		Description: "Show this help message.",
	},
}
