// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	"regexp"
	"strings"

	"maunium.net/go/mautrix/id"
)

var HTMLReplyFallbackRegex = regexp.MustCompile(`^<mx-reply>[\s\S]+?</mx-reply>`)

func TrimReplyFallbackHTML(html string) string {
	return HTMLReplyFallbackRegex.ReplaceAllString(html, "")
}

func TrimReplyFallbackText(text string) string {
	if (!strings.HasPrefix(text, "> <") && !strings.HasPrefix(text, "> * <")) || !strings.Contains(text, "\n") {
		return text
	}

	lines := strings.Split(text, "\n")
	for len(lines) > 0 && strings.HasPrefix(lines[0], "> ") {
		lines = lines[1:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func (content *MessageEventContent) RemoveReplyFallback() {
	if len(content.RelatesTo.GetReplyTo()) > 0 && !content.replyFallbackRemoved {
		if content.Format == FormatHTML {
			content.FormattedBody = TrimReplyFallbackHTML(content.FormattedBody)
		}
		content.Body = TrimReplyFallbackText(content.Body)
		content.replyFallbackRemoved = true
	}
}

// Deprecated: RelatesTo methods are nil-safe, so RelatesTo.GetReplyTo can be used directly
func (content *MessageEventContent) GetReplyTo() id.EventID {
	return content.RelatesTo.GetReplyTo()
}

func (content *MessageEventContent) SetReply(inReplyTo *Event) {
	content.RelatesTo = (&RelatesTo{}).SetReplyTo(inReplyTo.ID)
}
