// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"fmt"
	"mime"
	"strings"

	"go.mau.fi/util/jsontime"
)

type RoomFeatures struct {
	Formatting FormattingFeatureMap `json:"formatting,omitempty"`
	File       FileFeatureMap       `json:"file,omitempty"`

	LocationMessage CapabilitySupportLevel `json:"location_message,omitempty"`
	Poll            CapabilitySupportLevel `json:"poll,omitempty"`
	Thread          CapabilitySupportLevel `json:"thread,omitempty"`
	Reply           CapabilitySupportLevel `json:"reply,omitempty"`

	Edit         CapabilitySupportLevel `json:"edit,omitempty"`
	EditMaxCount int                    `json:"edit_max_count,omitempty"`
	EditMaxAge   *jsontime.Seconds      `json:"edit_max_age,omitempty"`
	Delete       CapabilitySupportLevel `json:"delete,omitempty"`
	DeleteForMe  bool                   `json:"delete_for_me,omitempty"`
	DeleteMaxAge *jsontime.Seconds      `json:"delete_max_age,omitempty"`

	Reaction             CapabilitySupportLevel `json:"reaction,omitempty"`
	ReactionCount        int                    `json:"reaction_count,omitempty"`
	AllowedReactions     []string               `json:"allowed_reactions,omitempty"`
	CustomEmojiReactions bool                   `json:"custom_emoji_reactions,omitempty"`

	ReadReceipts        bool `json:"read_receipts,omitempty"`
	TypingNotifications bool `json:"typing_notifications,omitempty"`
	Archive             bool `json:"archive,omitempty"`
	MarkAsUnread        bool `json:"mark_as_unread,omitempty"`
	DeleteChat          bool `json:"delete_chat,omitempty"`
}

type FormattingFeatureMap map[FormattingFeature]CapabilitySupportLevel

type FileFeatureMap map[CapabilityMsgType]*FileFeatures

type CapabilityMsgType = MessageType

// Message types which are used for event capability signaling, but aren't real values for the msgtype field.
const (
	CapMsgVoice   CapabilityMsgType = "org.matrix.msc3245.voice"
	CapMsgGIF     CapabilityMsgType = "fi.mau.gif"
	CapMsgSticker CapabilityMsgType = "m.sticker"
)

type CapabilitySupportLevel int

func (csl CapabilitySupportLevel) Partial() bool {
	return csl >= CapLevelPartialSupport
}

func (csl CapabilitySupportLevel) Full() bool {
	return csl >= CapLevelFullySupported
}

func (csl CapabilitySupportLevel) Reject() bool {
	return csl <= CapLevelRejected
}

const (
	CapLevelRejected       CapabilitySupportLevel = -2 // The feature is unsupported and messages using it will be rejected.
	CapLevelDropped        CapabilitySupportLevel = -1 // The feature is unsupported and has no fallback. The message will go through, but data may be lost.
	CapLevelUnsupported    CapabilitySupportLevel = 0  // The feature is unsupported, but may have a fallback.
	CapLevelPartialSupport CapabilitySupportLevel = 1  // The feature is partially supported (e.g. it may be converted to a different format).
	CapLevelFullySupported CapabilitySupportLevel = 2  // The feature is fully supported and can be safely used.
)

type FormattingFeature string

const (
	FmtBold                FormattingFeature = "bold"                           // strong, b
	FmtItalic              FormattingFeature = "italic"                         // em, i
	FmtUnderline           FormattingFeature = "underline"                      // u
	FmtStrikethrough       FormattingFeature = "strikethrough"                  // del, s
	FmtInlineCode          FormattingFeature = "inline_code"                    // code
	FmtCodeBlock           FormattingFeature = "code_block"                     // pre + code
	FmtSyntaxHighlighting  FormattingFeature = "code_block.syntax_highlighting" // <pre><code class="language-...">
	FmtBlockquote          FormattingFeature = "blockquote"                     // blockquote
	FmtInlineLink          FormattingFeature = "inline_link"                    // a
	FmtUserLink            FormattingFeature = "user_link"                      // <a href="https://matrix.to/#/@...">
	FmtRoomLink            FormattingFeature = "room_link"                      // <a href="https://matrix.to/#/#...">
	FmtEventLink           FormattingFeature = "event_link"                     // <a href="https://matrix.to/#/!.../$...">
	FmtAtRoomMention       FormattingFeature = "at_room_mention"                // @room (no html tag)
	FmtUnorderedList       FormattingFeature = "unordered_list"                 // ul + li
	FmtOrderedList         FormattingFeature = "ordered_list"                   // ol + li
	FmtListStart           FormattingFeature = "ordered_list.start"             // <ol start="N">
	FmtListJumpValue       FormattingFeature = "ordered_list.jump_value"        // <li value="N">
	FmtCustomEmoji         FormattingFeature = "custom_emoji"                   // <img data-mx-emoticon>
	FmtSpoiler             FormattingFeature = "spoiler"                        // <span data-mx-spoiler>
	FmtSpoilerReason       FormattingFeature = "spoiler.reason"                 // <span data-mx-spoiler="...">
	FmtTextForegroundColor FormattingFeature = "color.foreground"               // <span data-mx-color="#...">
	FmtTextBackgroundColor FormattingFeature = "color.background"               // <span data-mx-bg-color="#...">
	FmtHorizontalLine      FormattingFeature = "horizontal_line"                // hr
	FmtHeaders             FormattingFeature = "headers"                        // h1, h2, h3, h4, h5, h6
	FmtSuperscript         FormattingFeature = "superscript"                    // sup
	FmtSubscript           FormattingFeature = "subscript"                      // sub
	FmtMath                FormattingFeature = "math"                           // <span data-mx-maths="...">
	FmtDetailsSummary      FormattingFeature = "details_summary"                // <details><summary>...</summary>...</details>
	FmtTable               FormattingFeature = "table"                          // table, thead, tbody, tr, th, td
)

type FileFeatures struct {
	MimeTypes map[string]CapabilitySupportLevel `json:"mime_types"`

	Caption          CapabilitySupportLevel `json:"caption,omitempty"`
	MaxCaptionLength int                    `json:"max_caption_length,omitempty"`

	MaxSize     int64             `json:"max_size,omitempty"`
	MaxWidth    int               `json:"max_width,omitempty"`
	MaxHeight   int               `json:"max_height,omitempty"`
	MaxDuration *jsontime.Seconds `json:"max_duration,omitempty"`

	ViewOnce bool `json:"view_once,omitempty"`
}

func (ff *FileFeatures) GetMimeSupport(inputType string) CapabilitySupportLevel {
	match, ok := ff.MimeTypes[inputType]
	if ok {
		return match
	}
	if strings.IndexByte(inputType, ';') != -1 {
		plainMime, _, _ := mime.ParseMediaType(inputType)
		if plainMime != "" {
			if match, ok = ff.MimeTypes[plainMime]; ok {
				return match
			}
		}
	}
	if slash := strings.IndexByte(inputType, '/'); slash > 0 {
		generalType := fmt.Sprintf("%s/*", inputType[:slash])
		if match, ok = ff.MimeTypes[generalType]; ok {
			return match
		}
	}
	match, ok = ff.MimeTypes["*/*"]
	if ok {
		return match
	}
	return CapLevelRejected
}
