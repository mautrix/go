package gomatrix

import (
	"html"
	"regexp"
	"encoding/json"
)

type EventType string
type MessageType string

// State events
const (
	StateAliases        EventType = "m.room.aliases"
	StateCanonicalAlias           = "m.room.canonical_alias"
	StateCreate                   = "m.room.create"
	StateJoinRules                = "m.room.join_rules"
	StateMember                   = "m.room.member"
	StatePowerLevels              = "m.room.power_levels"
	StateRoomName                 = "m.room.name"
	StateTopic                    = "m.room.topic"
	StateRoomAvatar               = "m.room.avatar"
	StatePinnedEvents             = "m.room.pinned_events"
)

// Message events
const (
	EventRedaction EventType = "m.room.redaction"
	EventMessage             = "m.room.message"
	EventSticker             = "m.sticker"
)

// Msgtypes
const (
	MsgText     MessageType = "m.text"
	MsgEmote                = "m.emote"
	MsgNotice               = "m.notice"
	MsgImage                = "m.image"
	MsgLocation             = "m.location"
	MsgVideo                = "m.video"
	MsgAudio                = "m.audio"
	MsgFile                 = "m.file"
)

type Format string

// Message formats
const (
	FormatHTML Format = "org.matrix.custom.html"
)

// Event represents a single Matrix event.
type Event struct {
	StateKey  *string   `json:"state_key,omitempty"` // The state key for the event. Only present on State Events.
	Sender    string    `json:"sender"`              // The user ID of the sender of the event
	Type      EventType `json:"type"`                // The event type
	Timestamp int64     `json:"origin_server_ts"`    // The unix timestamp when this message was sent by the origin server
	ID        string    `json:"event_id"`            // The unique ID of this event
	RoomID    string    `json:"room_id"`             // The room the event was sent to. May be nil (e.g. for presence)
	Content   Content   `json:"content"`             // The JSON content of the event.
	Redacts   string    `json:"redacts,omitempty"`   // The event ID that was redacted if a m.room.redaction event
	Unsigned  Unsigned  `json:"unsigned,omitempty"`  // Unsigned content set by own homeserver.
}

func (evt *Event) GetStateKey() string {
	if evt.StateKey != nil {
		return *evt.StateKey
	}
	return ""
}

type Unsigned struct {
	PrevContent   map[string]interface{} `json:"prev_content,omitempty"`
	PrevSender    string                 `json:"prev_sender,omitempty"`
	ReplacesState string                 `json:"replaces_state,omitempty"`
	Age           int64                  `json:"age,omitempty"`
}
type Content struct {
	Raw map[string]interface{} `json:"-"`

	MsgType       MessageType `json:"msgtype,omitempty"`
	Body          string      `json:"body,omitempty"`
	Format        Format      `json:"format,omitempty"`
	FormattedBody string      `json:"formatted_body,omitempty"`

	Info FileInfo `json:"info,omitempty"`
	URL  string   `json:"url,omitempty"`

	Membership string `json:"membership,omitempty"`

	RelatesTo RelatesTo `json:"m.relates_to,omitempty"`
}

type serializableContent Content

func (content *Content) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &content.Raw); err != nil {
		return err
	}
	return json.Unmarshal(data, (*serializableContent)(content))
}

type FileInfo struct {
	MimeType      string    `json:"mimetype,omitempty"`
	ThumbnailInfo *FileInfo `json:"thumbnail_info,omitempty"`
	ThumbnailURL  string    `json:"thumbnail_url,omitempty"`
	Height        int       `json:"h,omitempty"`
	Width         int       `json:"w,omitempty"`
	Duration      uint      `json:"duration,omitempty"`
	Size          int       `json:"size,omitempty"`
}

type RelatesTo struct {
	InReplyTo InReplyTo `json:"m.in_reply_to,omitempty"`
}

type InReplyTo struct {
	EventID string `json:"event_id,omitempty"`
	// Not required, just for future-proofing
	RoomID string `json:"room_id,omitempty"`
}

var htmlRegex = regexp.MustCompile("<[^<]+?>")

// GetHTMLMessage returns an HTMLMessage with the body set to a stripped version of the provided HTML, in addition
// to the provided HTML.
func GetHTMLMessage(msgtype MessageType, htmlText string) Content {
	return Content{
		Body:          html.UnescapeString(htmlRegex.ReplaceAllLiteralString(htmlText, "")),
		MsgType:       msgtype,
		Format:        "org.matrix.custom.html",
		FormattedBody: htmlText,
	}
}
