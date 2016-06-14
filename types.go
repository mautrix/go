package mautrix

// Room events
const (
	EvtRoomAliases           = "m.room.aliases"
	EvtRoomCanonicalAlias    = "m.room.canonical_alias"
	EvtRoomCreate            = "m.room.create"
	EvtRoomJoinRules         = "m.room.join_rules"
	EvtRoomMember            = "m.room.member"
	EvtRoomPowerLevels       = "m.room.power_levels"
	EvtRoomRedaction         = "m.room.redaction"
	EvtRoomHistoryVisibility = "m.room.history_visibility"
	EvtRoomThirdPartyInvite  = "m.room.third_party_invite"
	EvtRoomGuestAccess       = "m.room.guest_access"
)

// Instant messaging events
const (
	EvtRoomMessage         = "m.room.message"
	EvtRoomMessageFeedback = "m.room.message.feedback"
	EvtRoomName            = "m.room.name"
	EvtRoomTopic           = "m.room.topic"
	EvtRoomAvatar          = "m.room.avatar"
)

// Message types
const (
	MsgText     = "m.text"
	MsgEmote    = "m.emote"
	MsgNotice   = "m.notice"
	MsgImage    = "m.image"
	MsgFile     = "m.file"
	MsgLocation = "m.location"
	MsgVideo    = "m.video"
	MsgAudio    = "m.audio"
)

// Login types
const (
	LoginPassword   = "m.login.password"
	LoginReCAPTCHA  = "m.login.recaptcha"
	LoginOAuth2     = "m.login.oauth2"
	LoginEmailIdent = "m.login.email.identity"
	LoginToken      = "m.login.token"
	LoginDummy      = "m.login.dummy"
)

// VoIP events
const (
	EvtCallInvite     = "m.call.invite"
	EvtCallCandidates = "m.call.candidates"
	EvtCallAnswer     = "m.call.answer"
	EvtCallHangup     = "m.call.hangup"
)

// Presence events
const (
	EvtTyping   = "m.typing"
	EvtReceipt  = "m.receipt"
	EvtRead     = "m.read"
	EvtPresence = "m.presence"
)

// Room tagging
const (
	EvtTag = "m.tag"
)
