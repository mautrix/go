// Copyright 2019 Tulir Asokan
package mautrix

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
)

type EventTypeClass int

const (
	// Normal message events
	MessageEventType EventTypeClass = iota
	// State events
	StateEventType
	// Ephemeral events
	EphemeralEventType
	// Account data events
	AccountDataEventType
	// Unknown events
	UnknownEventType
)

type EventType struct {
	Type  string
	Class EventTypeClass
}

func NewEventType(name string) EventType {
	evtType := EventType{Type: name}
	evtType.Class = evtType.GuessClass()
	return evtType
}

func (et *EventType) IsState() bool {
	return et.Class == StateEventType
}

func (et *EventType) IsEphemeral() bool {
	return et.Class == EphemeralEventType
}

func (et *EventType) IsAccountData() bool {
	return et.Class == AccountDataEventType
}

func (et *EventType) IsCustom() bool {
	return !strings.HasPrefix(et.Type, "m.")
}

func (et *EventType) GuessClass() EventTypeClass {
	switch et.Type {
	case StateAliases.Type, StateCanonicalAlias.Type, StateCreate.Type, StateJoinRules.Type, StateMember.Type,
		StatePowerLevels.Type, StateRoomName.Type, StateRoomAvatar.Type, StateTopic.Type, StatePinnedEvents.Type:
		return StateEventType
	case EphemeralEventReceipt.Type, EphemeralEventTyping.Type:
		return EphemeralEventType
	case AccountDataDirectChats.Type, AccountDataPushRules.Type, AccountDataRoomTags.Type:
		return AccountDataEventType
	case EventRedaction.Type, EventMessage.Type, EventSticker.Type:
		return MessageEventType
	default:
		return UnknownEventType
	}
}

func (et *EventType) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &et.Type)
	if err != nil {
		return err
	}
	et.Class = et.GuessClass()
	return nil
}

func (et *EventType) MarshalJSON() ([]byte, error) {
	return json.Marshal(&et.Type)
}

func (et *EventType) String() string {
	return et.Type
}

// State events
var (
	StateAliases        = EventType{"m.room.aliases", StateEventType}
	StateCanonicalAlias = EventType{"m.room.canonical_alias", StateEventType}
	StateCreate         = EventType{"m.room.create", StateEventType}
	StateJoinRules      = EventType{"m.room.join_rules", StateEventType}
	StateMember         = EventType{"m.room.member", StateEventType}
	StatePowerLevels    = EventType{"m.room.power_levels", StateEventType}
	StateRoomName       = EventType{"m.room.name", StateEventType}
	StateTopic          = EventType{"m.room.topic", StateEventType}
	StateRoomAvatar     = EventType{"m.room.avatar", StateEventType}
	StatePinnedEvents   = EventType{"m.room.pinned_events", StateEventType}
)

// Message events
var (
	EventRedaction = EventType{"m.room.redaction", MessageEventType}
	EventMessage   = EventType{"m.room.message", MessageEventType}
	EventEncrypted = EventType{"m.room.encrypted", MessageEventType}
	EventReaction  = EventType{"m.reaction", MessageEventType}
	EventSticker   = EventType{"m.sticker", MessageEventType}
)

// Ephemeral events
var (
	EphemeralEventReceipt = EventType{"m.receipt", EphemeralEventType}
	EphemeralEventTyping  = EventType{"m.typing", EphemeralEventType}
)

// Account data events
var (
	AccountDataDirectChats = EventType{"m.direct", AccountDataEventType}
	AccountDataPushRules   = EventType{"m.push_rules", AccountDataEventType}
	AccountDataRoomTags    = EventType{"m.tag", AccountDataEventType}
)

type MessageType string

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

	InviteRoomState []StrippedState `json:"invite_room_state"`
}

func (evt *Event) GetStateKey() string {
	if evt.StateKey != nil {
		return *evt.StateKey
	}
	return ""
}

type StrippedState struct {
	Content  Content   `json:"content"`
	Type     EventType `json:"type"`
	StateKey string    `json:"state_key"`
}

type Unsigned struct {
	PrevContent     *Content  `json:"prev_content,omitempty"`
	PrevSender      string    `json:"prev_sender,omitempty"`
	ReplacesState   string    `json:"replaces_state,omitempty"`
	Age             int64     `json:"age,omitempty"`
	TransactionID   string    `json:"transaction_id,omitempty"`
	Relations       Relations `json:"m.relations,omitempty"`
	RedactedBy      string    `json:"redacted_by,omitempty"`
	RedactedBecause *Event    `json:"redacted_because,omitempty"`
}

type Content struct {
	VeryRaw json.RawMessage        `json:"-"`
	Raw     map[string]interface{} `json:"-"`

	MsgType       MessageType `json:"msgtype,omitempty"`
	Body          string      `json:"body,omitempty"`
	Format        Format      `json:"format,omitempty"`
	FormattedBody string      `json:"formatted_body,omitempty"`

	Info *FileInfo `json:"info,omitempty"`
	URL  string    `json:"url,omitempty"`

	// Membership key for easy access in m.room.member events
	Membership Membership `json:"membership,omitempty"`

	NewContent *Content   `json:"m.new_content,omitempty"`
	RelatesTo  *RelatesTo `json:"m.relates_to,omitempty"`

	*PowerLevels
	Member
	Aliases []string `json:"aliases,omitempty"`
	Alias   string   `json:"alias,omitempty"`
	Name    string   `json:"name,omitempty"`
	Topic   string   `json:"topic,omitempty"`

	RoomTags      Tags     `json:"tags,omitempty"`
	TypingUserIDs []string `json:"user_ids,omitempty"`
}

type serializableContent Content

var DisableFancyEventParsing = false

func (content *Content) UnmarshalJSON(data []byte) error {
	content.VeryRaw = data
	if err := json.Unmarshal(data, &content.Raw); err != nil || DisableFancyEventParsing {
		return err
	}
	return json.Unmarshal(data, (*serializableContent)(content))
}

func (content *Content) GetRelatesTo() *RelatesTo {
	if content.RelatesTo == nil {
		content.RelatesTo = &RelatesTo{}
	}
	return content.RelatesTo
}

func (content *Content) GetPowerLevels() *PowerLevels {
	if content.PowerLevels == nil {
		content.PowerLevels = &PowerLevels{}
	}
	return content.PowerLevels
}

func (content *Content) UnmarshalPowerLevels() (pl PowerLevels, err error) {
	err = json.Unmarshal(content.VeryRaw, &pl)
	return
}

func (content *Content) UnmarshalMember() (m Member, err error) {
	err = json.Unmarshal(content.VeryRaw, &m)
	return
}

func (content *Content) GetInfo() *FileInfo {
	if content.Info == nil {
		content.Info = &FileInfo{}
	}
	return content.Info
}

type Tags map[string]Tag

type Tag struct {
	Order json.Number `json:"order,omitempty"`
}

// Membership is an enum specifying the membership state of a room member.
type Membership string

func (ms Membership) IsInviteOrJoin() bool {
	return ms == MembershipJoin || ms == MembershipInvite
}

func (ms Membership) IsLeaveOrBan() bool {
	return ms == MembershipLeave || ms == MembershipBan
}

// The allowed membership states as specified in spec section 10.5.5.
const (
	MembershipJoin   Membership = "join"
	MembershipLeave  Membership = "leave"
	MembershipInvite Membership = "invite"
	MembershipBan    Membership = "ban"
	MembershipKnock  Membership = "knock"
)

type Member struct {
	Membership       Membership        `json:"membership,omitempty"`
	AvatarURL        string            `json:"avatar_url,omitempty"`
	Displayname      string            `json:"displayname,omitempty"`
	IsDirect         bool              `json:"is_direct,omitempty"`
	ThirdPartyInvite *ThirdPartyInvite `json:"third_party_invite,omitempty"`
	Reason           string            `json:"reason,omitempty"`
}

type ThirdPartyInvite struct {
	DisplayName string `json:"display_name"`
	Signed      struct {
		Token      string          `json:"token"`
		Signatures json.RawMessage `json:"signatures"`
		MXID       string          `json:"mxid"`
	}
}

type PowerLevels struct {
	usersLock    sync.RWMutex   `json:"-"`
	Users        map[string]int `json:"users"`
	UsersDefault int            `json:"users_default"`

	eventsLock    sync.RWMutex   `json:"-"`
	Events        map[string]int `json:"events"`
	EventsDefault int            `json:"events_default"`

	StateDefaultPtr *int `json:"state_default,omitempty"`

	InvitePtr *int `json:"invite,omitempty"`
	KickPtr   *int `json:"kick,omitempty"`
	BanPtr    *int `json:"ban,omitempty"`
	RedactPtr *int `json:"redact,omitempty"`
}

func (pl *PowerLevels) Invite() int {
	if pl.InvitePtr != nil {
		return *pl.InvitePtr
	}
	return 50
}

func (pl *PowerLevels) Kick() int {
	if pl.KickPtr != nil {
		return *pl.KickPtr
	}
	return 50
}

func (pl *PowerLevels) Ban() int {
	if pl.BanPtr != nil {
		return *pl.BanPtr
	}
	return 50
}

func (pl *PowerLevels) Redact() int {
	if pl.RedactPtr != nil {
		return *pl.RedactPtr
	}
	return 50
}

func (pl *PowerLevels) StateDefault() int {
	if pl.StateDefaultPtr != nil {
		return *pl.StateDefaultPtr
	}
	return 50
}

func (pl *PowerLevels) GetUserLevel(userID string) int {
	pl.usersLock.RLock()
	defer pl.usersLock.RUnlock()
	level, ok := pl.Users[userID]
	if !ok {
		return pl.UsersDefault
	}
	return level
}

func (pl *PowerLevels) SetUserLevel(userID string, level int) {
	pl.usersLock.Lock()
	defer pl.usersLock.Unlock()
	if level == pl.UsersDefault {
		delete(pl.Users, userID)
	} else {
		pl.Users[userID] = level
	}
}

func (pl *PowerLevels) EnsureUserLevel(userID string, level int) bool {
	existingLevel := pl.GetUserLevel(userID)
	if existingLevel != level {
		pl.SetUserLevel(userID, level)
		return true
	}
	return false
}

func (pl *PowerLevels) GetEventLevel(eventType EventType) int {
	pl.eventsLock.RLock()
	defer pl.eventsLock.RUnlock()
	level, ok := pl.Events[eventType.String()]
	if !ok {
		if eventType.IsState() {
			return pl.StateDefault()
		}
		return pl.EventsDefault
	}
	return level
}

func (pl *PowerLevels) SetEventLevel(eventType EventType, level int) {
	pl.eventsLock.Lock()
	defer pl.eventsLock.Unlock()
	if (eventType.IsState() && level == pl.StateDefault()) || (!eventType.IsState() && level == pl.EventsDefault) {
		delete(pl.Events, eventType.String())
	} else {
		pl.Events[eventType.String()] = level
	}
}

func (pl *PowerLevels) EnsureEventLevel(eventType EventType, level int) bool {
	existingLevel := pl.GetEventLevel(eventType)
	if existingLevel != level {
		pl.SetEventLevel(eventType, level)
		return true
	}
	return false
}

type FileInfo struct {
	MimeType      string    `json:"mimetype,omitempty"`
	ThumbnailInfo *FileInfo `json:"thumbnail_info,omitempty"`
	ThumbnailURL  string    `json:"thumbnail_url,omitempty"`
	Width         int       `json:"-"`
	Height        int       `json:"-"`
	Duration      uint      `json:"-"`
	Size          int       `json:"-"`
}

type serializableFileInfo struct {
	MimeType      string                `json:"mimetype,omitempty"`
	ThumbnailInfo *serializableFileInfo `json:"thumbnail_info,omitempty"`
	ThumbnailURL  string                `json:"thumbnail_url,omitempty"`

	Width    json.Number `json:"w,omitempty"`
	Height   json.Number `json:"h,omitempty"`
	Duration json.Number `json:"duration,omitempty"`
	Size     json.Number `json:"size,omitempty"`
}

func (sfi *serializableFileInfo) CopyFrom(fileInfo *FileInfo) *serializableFileInfo {
	if fileInfo == nil {
		return nil
	}
	*sfi = serializableFileInfo{
		Width:         json.Number(strconv.Itoa(fileInfo.Width)),
		Height:        json.Number(strconv.Itoa(fileInfo.Height)),
		Size:          json.Number(strconv.Itoa(fileInfo.Size)),
		Duration:      json.Number(strconv.Itoa(int(fileInfo.Duration))),
		MimeType:      fileInfo.MimeType,
		ThumbnailURL:  fileInfo.ThumbnailURL,
		ThumbnailInfo: (&serializableFileInfo{}).CopyFrom(fileInfo.ThumbnailInfo),
	}
	return sfi
}

func (sfi *serializableFileInfo) CopyTo(fileInfo *FileInfo) {
	*fileInfo = FileInfo{
		Width:        int(numberToUint(sfi.Width)),
		Height:       int(numberToUint(sfi.Height)),
		Size:         int(numberToUint(sfi.Size)),
		Duration:     numberToUint(sfi.Duration),
		MimeType:     sfi.MimeType,
		ThumbnailURL: sfi.ThumbnailURL,
	}
	if sfi.ThumbnailInfo != nil {
		fileInfo.ThumbnailInfo = &FileInfo{}
		sfi.ThumbnailInfo.CopyTo(fileInfo.ThumbnailInfo)
	}
}

func (fileInfo *FileInfo) UnmarshalJSON(data []byte) error {
	sfi := &serializableFileInfo{}
	if err := json.Unmarshal(data, sfi); err != nil {
		return err
	}
	sfi.CopyTo(fileInfo)
	return nil
}

func (fileInfo *FileInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal((&serializableFileInfo{}).CopyFrom(fileInfo))
}

func numberToUint(val json.Number) uint {
	f64, _ := val.Float64()
	if f64 > 0 {
		return uint(f64)
	}
	return 0
}

func (fileInfo *FileInfo) GetThumbnailInfo() *FileInfo {
	if fileInfo.ThumbnailInfo == nil {
		fileInfo.ThumbnailInfo = &FileInfo{}
	}
	return fileInfo.ThumbnailInfo
}
