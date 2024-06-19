// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/configupgrade"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mediaproxy"
)

type ConvertedMessagePart struct {
	ID         networkid.PartID
	Type       event.Type
	Content    *event.MessageEventContent
	Extra      map[string]any
	DBMetadata map[string]any
}

type EventSender struct {
	IsFromMe    bool
	SenderLogin networkid.UserLoginID
	Sender      networkid.UserID
}

type ConvertedMessage struct {
	ReplyTo    *networkid.MessageOptionalPartID
	ThreadRoot *networkid.MessageOptionalPartID
	Parts      []*ConvertedMessagePart
	Disappear  database.DisappearingSetting
}

type ConvertedEditPart struct {
	Part *database.Message

	Type event.Type
	// The Content and Extra fields will be put inside `m.new_content` automatically.
	// SetEdit must NOT be called by the network connector.
	Content *event.MessageEventContent
	Extra   map[string]any
	// TopLevelExtra can be used to specify custom fields at the top level of the content rather than inside `m.new_content`.
	TopLevelExtra map[string]any
}

type ConvertedEdit struct {
	ModifiedParts []*ConvertedEditPart
	DeletedParts  []*database.Message
}

// BridgeName contains information about the network that a connector bridges to.
type BridgeName struct {
	// The displayname of the network, e.g. `Discord`
	DisplayName string
	// The URL to the website of the network, e.g. `https://discord.com`
	NetworkURL string
	// The icon of the network as a mxc:// URI
	NetworkIcon id.ContentURIString
	// An identifier uniquely identifying the network, e.g. `discord`
	NetworkID string
	// An identifier uniquely identifying the bridge software, e.g. `discordgo`
	BeeperBridgeType string
	// The default appservice port to use in the example config, defaults to 8080 if unset
	DefaultPort uint16
	// The default command prefix to use in the example config, defaults to NetworkID if unset. Must include the ! prefix.
	DefaultCommandPrefix string
}

func (bn BridgeName) AsBridgeInfoSection() event.BridgeInfoSection {
	return event.BridgeInfoSection{
		ID:          bn.BeeperBridgeType,
		DisplayName: bn.DisplayName,
		AvatarURL:   bn.NetworkIcon,
		ExternalURL: bn.NetworkURL,
	}
}

// NetworkConnector is the main interface that a network connector must implement.
type NetworkConnector interface {
	// Init is called when the bridge is initialized. The connector should store the bridge instance for later use.
	// This should not do any network calls or other blocking operations.
	Init(*Bridge)
	// Start is called when the bridge is starting.
	// The connector should do any non-user-specific startup actions necessary.
	// User logins will be loaded separately, so the connector should not load them here.
	Start(context.Context) error
	// LoadUserLogin is called when a UserLogin is loaded from the database in order to fill the [UserLogin.Client] field.
	//
	// This is called within the bridge's global cache lock, so it must not do any slow operations,
	// such as connecting to the network. Instead, connecting should happen when [NetworkAPI.Connect] is called later.
	LoadUserLogin(ctx context.Context, login *UserLogin) error

	GetName() BridgeName
	// GetConfig returns all the parts of the network connector's config file. Specifically:
	// - example: a string containing an example config file
	// - data: an interface to unmarshal the actual config into
	// - upgrader: a config upgrader to ensure all fields are present and to do any migrations from old configs
	GetConfig() (example string, data any, upgrader configupgrade.Upgrader)

	// GetLoginFlows returns a list of login flows that the network supports.
	GetLoginFlows() []LoginFlow
	// CreateLogin is called when a user wants to log in to the network.
	//
	// This should generally not do any work, it should just return a LoginProcess that remembers
	// the user and will execute the requested flow. The actual work should start when [LoginProcess.Start] is called.
	CreateLogin(ctx context.Context, user *User, flowID string) (LoginProcess, error)
}

var ErrDirectMediaNotEnabled = errors.New("direct media is not enabled")

// DirectMediableNetwork is an optional interface that network connectors can implement to support direct media access.
//
// If the Matrix connector has direct media enabled, SetUseDirectMedia will be called
// before the Start method of the network connector. Download will then be called
// whenever someone wants to download a direct media `mxc://` URI which was generated
// by calling GenerateContentURI on the Matrix connector.
type DirectMediableNetwork interface {
	NetworkConnector
	SetUseDirectMedia()
	Download(ctx context.Context, mediaID networkid.MediaID) (mediaproxy.GetMediaResponse, error)
}

// ConfigValidatingNetwork is an optional interface that network connectors can implement to validate config fields
// before the bridge is started.
//
// When the ValidateConfig method is called, the config data will already be unmarshaled into the
// object returned by [NetworkConnector.GetConfig].
//
// This mechanism is usually used to refuse bridge startup if a mandatory field has an invalid value.
type ConfigValidatingNetwork interface {
	NetworkConnector
	ValidateConfig() error
}

// MaxFileSizeingNetwork is an optional interface that network connectors can implement
// to find out the maximum file size that can be uploaded to Matrix.
//
// The SetMaxFileSize will be called asynchronously soon after startup.
// Before the function is called, the connector may assume a default limit of 50 MiB.
type MaxFileSizeingNetwork interface {
	NetworkConnector
	SetMaxFileSize(maxSize int64)
}

type MatrixMessageResponse struct {
	DB *database.Message
}

// NetworkAPI is an interface representing a remote network client for a single user login.
type NetworkAPI interface {
	Connect(ctx context.Context) error
	Disconnect()
	IsLoggedIn() bool
	LogoutRemote(ctx context.Context)

	IsThisUser(ctx context.Context, userID networkid.UserID) bool
	GetChatInfo(ctx context.Context, portal *Portal) (*PortalInfo, error)
	GetUserInfo(ctx context.Context, ghost *Ghost) (*UserInfo, error)

	HandleMatrixMessage(ctx context.Context, msg *MatrixMessage) (message *MatrixMessageResponse, err error)
	HandleMatrixEdit(ctx context.Context, msg *MatrixEdit) error
	PreHandleMatrixReaction(ctx context.Context, msg *MatrixReaction) (MatrixReactionPreResponse, error)
	HandleMatrixReaction(ctx context.Context, msg *MatrixReaction) (reaction *database.Reaction, err error)
	HandleMatrixReactionRemove(ctx context.Context, msg *MatrixReactionRemove) error
	HandleMatrixMessageRemove(ctx context.Context, msg *MatrixMessageRemove) error
	HandleMatrixReadReceipt(ctx context.Context, msg *MatrixReadReceipt) error
	HandleMatrixTyping(ctx context.Context, msg *MatrixTyping) error
}

type PushType int

func (pt PushType) String() string {
	return pt.GoString()
}

func PushTypeFromString(str string) PushType {
	switch strings.TrimPrefix(strings.ToLower(str), "pushtype") {
	case "web":
		return PushTypeWeb
	case "apns":
		return PushTypeAPNs
	case "fcm":
		return PushTypeFCM
	default:
		return PushTypeUnknown
	}
}

func (pt PushType) GoString() string {
	switch pt {
	case PushTypeUnknown:
		return "PushTypeUnknown"
	case PushTypeWeb:
		return "PushTypeWeb"
	case PushTypeAPNs:
		return "PushTypeAPNs"
	case PushTypeFCM:
		return "PushTypeFCM"
	default:
		return fmt.Sprintf("PushType(%d)", int(pt))
	}
}

const (
	PushTypeUnknown PushType = iota
	PushTypeWeb
	PushTypeAPNs
	PushTypeFCM
)

type WebPushConfig struct {
	VapidKey string `json:"vapid_key"`
}

type FCMPushConfig struct {
	SenderID string `json:"sender_id"`
}

type APNsPushConfig struct {
	BundleID string `json:"bundle_id"`
}

type PushConfig struct {
	Web  *WebPushConfig  `json:"web,omitempty"`
	FCM  *FCMPushConfig  `json:"fcm,omitempty"`
	APNs *APNsPushConfig `json:"apns,omitempty"`
}

type PushableNetworkAPI interface {
	RegisterPushNotifications(ctx context.Context, pushType PushType, token string) error
	GetPushConfigs() *PushConfig
}

type RemoteEventType int

const (
	RemoteEventUnknown RemoteEventType = iota
	RemoteEventMessage
	RemoteEventEdit
	RemoteEventReaction
	RemoteEventReactionRemove
	RemoteEventMessageRemove
	RemoteEventReadReceipt
	RemoteEventDeliveryReceipt
	RemoteEventTyping
)

// RemoteEvent represents a single event from the remote network, such as a message or a reaction.
//
// When a [NetworkAPI] receives an event from the remote network, it should convert it into a [RemoteEvent]
// and pass it to the bridge for processing using [Bridge.QueueRemoteEvent].
type RemoteEvent interface {
	GetType() RemoteEventType
	GetPortalKey() networkid.PortalKey
	AddLogContext(c zerolog.Context) zerolog.Context
	GetSender() EventSender
}

type RemoteEventThatMayCreatePortal interface {
	RemoteEvent
	ShouldCreatePortal() bool
}

type RemoteEventWithTargetMessage interface {
	RemoteEvent
	GetTargetMessage() networkid.MessageID
}

type RemoteEventWithTargetPart interface {
	RemoteEventWithTargetMessage
	GetTargetMessagePart() networkid.PartID
}

type RemoteEventWithTimestamp interface {
	RemoteEvent
	GetTimestamp() time.Time
}

type RemoteMessage interface {
	RemoteEvent
	GetID() networkid.MessageID
	ConvertMessage(ctx context.Context, portal *Portal, intent MatrixAPI) (*ConvertedMessage, error)
}

type RemoteEdit interface {
	RemoteEventWithTargetMessage
	ConvertEdit(ctx context.Context, portal *Portal, intent MatrixAPI, existing []*database.Message) (*ConvertedEdit, error)
}

type RemoteReaction interface {
	RemoteEventWithTargetMessage
	GetReactionEmoji() (string, networkid.EmojiID)
}

type RemoteReactionWithMeta interface {
	RemoteReaction
	GetReactionDBMetadata() map[string]any
}

type RemoteReactionRemove interface {
	RemoteEventWithTargetMessage
	GetRemovedEmojiID() networkid.EmojiID
}

type RemoteMessageRemove interface {
	RemoteEventWithTargetMessage
}

type RemoteReceipt interface {
	RemoteEvent
	GetLastReceiptTarget() networkid.MessageID
	GetReceiptTargets() []networkid.MessageID
}

type RemoteTyping interface {
	RemoteEvent
	GetTimeout() time.Duration
}

type TypingType int

const (
	TypingTypeText TypingType = iota
	TypingTypeUploadingMedia
	TypingTypeRecordingMedia
)

type RemoteTypingWithType interface {
	RemoteTyping
	GetTypingType() TypingType
}

// SimpleRemoteEvent is a simple implementation of RemoteEvent that can be used with struct fields and some callbacks.
type SimpleRemoteEvent[T any] struct {
	Type         RemoteEventType
	LogContext   func(c zerolog.Context) zerolog.Context
	PortalKey    networkid.PortalKey
	Data         T
	CreatePortal bool

	ID             networkid.MessageID
	Sender         EventSender
	TargetMessage  networkid.MessageID
	EmojiID        networkid.EmojiID
	Emoji          string
	ReactionDBMeta map[string]any
	Timestamp      time.Time

	ConvertMessageFunc func(ctx context.Context, portal *Portal, intent MatrixAPI, data T) (*ConvertedMessage, error)
	ConvertEditFunc    func(ctx context.Context, portal *Portal, intent MatrixAPI, existing []*database.Message, data T) (*ConvertedEdit, error)
}

var (
	_ RemoteMessage            = (*SimpleRemoteEvent[any])(nil)
	_ RemoteEdit               = (*SimpleRemoteEvent[any])(nil)
	_ RemoteEventWithTimestamp = (*SimpleRemoteEvent[any])(nil)
	_ RemoteReaction           = (*SimpleRemoteEvent[any])(nil)
	_ RemoteReactionWithMeta   = (*SimpleRemoteEvent[any])(nil)
	_ RemoteReactionRemove     = (*SimpleRemoteEvent[any])(nil)
	_ RemoteMessageRemove      = (*SimpleRemoteEvent[any])(nil)
)

func (sre *SimpleRemoteEvent[T]) AddLogContext(c zerolog.Context) zerolog.Context {
	return sre.LogContext(c)
}

func (sre *SimpleRemoteEvent[T]) GetPortalKey() networkid.PortalKey {
	return sre.PortalKey
}

func (sre *SimpleRemoteEvent[T]) GetTimestamp() time.Time {
	if sre.Timestamp.IsZero() {
		return time.Now()
	}
	return sre.Timestamp
}

func (sre *SimpleRemoteEvent[T]) ConvertMessage(ctx context.Context, portal *Portal, intent MatrixAPI) (*ConvertedMessage, error) {
	return sre.ConvertMessageFunc(ctx, portal, intent, sre.Data)
}

func (sre *SimpleRemoteEvent[T]) ConvertEdit(ctx context.Context, portal *Portal, intent MatrixAPI, existing []*database.Message) (*ConvertedEdit, error) {
	return sre.ConvertEditFunc(ctx, portal, intent, existing, sre.Data)
}

func (sre *SimpleRemoteEvent[T]) GetID() networkid.MessageID {
	return sre.ID
}

func (sre *SimpleRemoteEvent[T]) GetSender() EventSender {
	return sre.Sender
}

func (sre *SimpleRemoteEvent[T]) GetTargetMessage() networkid.MessageID {
	return sre.TargetMessage
}

func (sre *SimpleRemoteEvent[T]) GetReactionEmoji() (string, networkid.EmojiID) {
	return sre.Emoji, sre.EmojiID
}

func (sre *SimpleRemoteEvent[T]) GetRemovedEmojiID() networkid.EmojiID {
	return sre.EmojiID
}

func (sre *SimpleRemoteEvent[T]) GetReactionDBMetadata() map[string]any {
	return sre.ReactionDBMeta
}

func (sre *SimpleRemoteEvent[T]) GetType() RemoteEventType {
	return sre.Type
}

func (sre *SimpleRemoteEvent[T]) ShouldCreatePortal() bool {
	return sre.CreatePortal
}

type OrigSender struct {
	User *User
	event.MemberEventContent
}

type MatrixEventBase[ContentType any] struct {
	// The raw event being bridged.
	Event *event.Event
	// The parsed content struct of the event. Custom fields can be found in Event.Content.Raw.
	Content ContentType
	// The room where the event happened.
	Portal *Portal

	// The original sender user ID. Only present in case the event is being relayed (and Sender is not the same user).
	OrigSender *OrigSender
}

type MatrixMessage struct {
	MatrixEventBase[*event.MessageEventContent]
	ThreadRoot *database.Message
	ReplyTo    *database.Message
}

type MatrixEdit struct {
	MatrixEventBase[*event.MessageEventContent]
	EditTarget *database.Message
}

type MatrixReaction struct {
	MatrixEventBase[*event.ReactionEventContent]
	TargetMessage *database.Message
	PreHandleResp *MatrixReactionPreResponse

	// When MaxReactions is >0 in the pre-response, this is the list of previous reactions that should be preserved.
	ExistingReactionsToKeep []*database.Reaction
}

type MatrixReactionPreResponse struct {
	SenderID     networkid.UserID
	EmojiID      networkid.EmojiID
	Emoji        string
	MaxReactions int
}

type MatrixReactionRemove struct {
	MatrixEventBase[*event.RedactionEventContent]
	TargetReaction *database.Reaction
}

type MatrixMessageRemove struct {
	MatrixEventBase[*event.RedactionEventContent]
	TargetMessage *database.Message
}

type MatrixReadReceipt struct {
	Portal *Portal
	// The event ID that the receipt is targeting
	EventID id.EventID
	// The exact message that was read. This may be nil if the event ID isn't a message.
	ExactMessage *database.Message
	// The timestamp that the user has read up to. This is either the timestamp of the message
	// (if one is present) or the timestamp of the receipt.
	ReadUpTo time.Time
	// The ReadUpTo timestamp of the previous message
	LastRead time.Time
	// The receipt metadata.
	Receipt event.ReadReceipt
}

type MatrixTyping struct {
	Portal   *Portal
	IsTyping bool
	Type     TypingType
}
