package gomatrix

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"maubot.xyz"
)

var HTMLReplyFallbackRegex = regexp.MustCompile(`^<mx-reply>[\s\S]+?</mx-reply>`)

func TrimReplyFallbackHTML(html string) string {
	return HTMLReplyFallbackRegex.ReplaceAllString(html, "")
}

func TrimReplyFallbackText(text string) string {
	if !strings.HasPrefix(text, "> ") || !strings.Contains(text, "\n") {
		return text
	}

	lines := strings.Split(text, "\n")
	for len(lines) > 0 && strings.HasPrefix(lines[0], "> ") {
		lines = lines[1:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func RemoveReplyFallback(evt *Event) {
	if len(evt.Content.RelatesTo.InReplyTo.EventID) > 0 {
		if evt.Content.Format == maubot.FormatHTML {
			evt.Content.FormattedBody = TrimReplyFallbackHTML(evt.Content.FormattedBody)
		}
		evt.Content.Body = TrimReplyFallbackText(evt.Content.Body)
	}
}

const ReplyFormat = `<mx-reply><blockquote>
<a href="https://matrix.to/#/%s/%s">In reply to</a>
<a href="https://matrix.to/#/%s">%s</a>
%s
</blockquote></mx-reply>
`

func ReplyFallbackHTML(evt *Event) string {
	body := evt.Content.FormattedBody
	if len(body) == 0 {
		body = html.EscapeString(evt.Content.Body)
	}

	senderDisplayName := evt.Sender

	return fmt.Sprintf(ReplyFormat, evt.RoomID, evt.ID, evt.Sender, senderDisplayName, body)
}

func ReplyFallbackText(evt *Event) string {
	body := evt.Content.Body
	lines := strings.Split(strings.TrimSpace(body), "\n")
	firstLine, lines := lines[0], lines[1:]

	senderDisplayName := evt.Sender

	var fallbackText strings.Builder
	fmt.Fprintf(&fallbackText, "> <%s> %s", senderDisplayName, firstLine)
	for _, line := range lines {
		fmt.Fprintf(&fallbackText, "\n> %s", line)
	}
	fallbackText.WriteString("\n\n")
	return fallbackText.String()
}

func SetReply(content maubot.Content, inReplyTo *Event) maubot.Content {
	content.RelatesTo.InReplyTo.EventID = inReplyTo.ID
	content.RelatesTo.InReplyTo.RoomID = inReplyTo.RoomID

	if content.MsgType == maubot.MsgText || content.MsgType == maubot.MsgNotice {
		if len(content.FormattedBody) == 0 || content.Format != maubot.FormatHTML {
			content.FormattedBody = html.EscapeString(content.Body)
			content.Format = maubot.FormatHTML
		}
		content.FormattedBody = ReplyFallbackHTML(inReplyTo) + content.FormattedBody
		content.Body = ReplyFallbackText(inReplyTo) + content.Body
	}

	return content
}