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
	// An identifier uniquely identifying the bridge software.
	// The Go import path is a good choice here (e.g. github.com/octocat/discordbridge)
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

	// GetName returns the name of the bridge and some additional metadata,
	// which is used to fill `m.bridge` events among other things.
	//
	// The first call happens *before* the config is loaded, because the data here is also used to
	// fill parts of the example config (like the default username template and bot localpart).
	// The output can still be adjusted based on config variables, but the function must have
	// default values when called without a config.
	GetName() BridgeName
	// GetCapabilities returns the general capabilities of the network connector.
	// Note that most capabilities are scoped to rooms and are returned by [NetworkAPI.GetCapabilities] instead.
	GetCapabilities() *NetworkGeneralCapabilities
	// GetConfig returns all the parts of the network connector's config file. Specifically:
	// - example: a string containing an example config file
	// - data: an interface to unmarshal the actual config into
	// - upgrader: a config upgrader to ensure all fields are present and to do any migrations from old configs
	GetConfig() (example string, data any, upgrader configupgrade.Upgrader)

	// LoadUserLogin is called when a UserLogin is loaded from the database in order to fill the [UserLogin.Client] field.
	//
	// This is called within the bridge's global cache lock, so it must not do any slow operations,
	// such as connecting to the network. Instead, connecting should happen when [NetworkAPI.Connect] is called later.
	LoadUserLogin(ctx context.Context, login *UserLogin) error

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

type FileRestriction struct {
	MaxSize   int64
	MimeTypes []string
}

type NetworkGeneralCapabilities struct {
	// Does the network connector support disappearing messages?
	// This flag enables the message disappearing loop in the bridge.
	DisappearingMessages bool
	// Should the bridge re-request user info on incoming messages even if the ghost already has info?
	// By default, info is only requested for ghosts with no name, and other updating is left to events.
	AggressiveUpdateInfo bool
}

type NetworkRoomCapabilities struct {
	FormattedText bool
	UserMentions  bool
	RoomMentions  bool

	LocationMessages bool
	Captions         bool
	MaxTextLength    int
	MaxCaptionLength int

	Threads      bool
	Replies      bool
	Edits        bool
	EditMaxCount int
	EditMaxAge   time.Duration
	Deletes      bool
	DeleteMaxAge time.Duration

	DefaultFileRestriction *FileRestriction
	Files                  map[event.MessageType]FileRestriction

	ReadReceipts bool

	Reactions        bool
	ReactionCount    int
	AllowedReactions []string
}

// NetworkAPI is an interface representing a remote network client for a single user login.
//
// Implementations of this interface are stored in [UserLogin.Client].
// The [NetworkConnector.LoadUserLogin] method is responsible for filling the Client field with a NetworkAPI.
type NetworkAPI interface {
	// Connect is called to actually connect to the remote network.
	// If there's no persistent connection, this may just check access token validity, or even do nothing at all.
	Connect(ctx context.Context) error
	// Disconnect should disconnect from the remote network.
	// A clean disconnection is preferred, but it should not take too long.
	Disconnect()
	// IsLoggedIn should return whether the access tokens in this NetworkAPI are valid.
	// This should not do any IO operations, it should only return cached data which is updated elsewhere.
	IsLoggedIn() bool
	// LogoutRemote should invalidate the access tokens in this NetworkAPI if possible
	// and disconnect from the remote network.
	LogoutRemote(ctx context.Context)

	// IsThisUser should return whether the given remote network user ID is the same as this login.
	// This is used when the bridge wants to convert a user login ID to a user ID.
	IsThisUser(ctx context.Context, userID networkid.UserID) bool
	// GetChatInfo returns info for a given chat. Any fields that are nil will be ignored and not processed at all,
	// while empty strings will change the relevant value in the room to be an empty string.
	// For example, a nil name will mean the room name is not changed, while an empty string name will remove the name.
	GetChatInfo(ctx context.Context, portal *Portal) (*ChatInfo, error)
	// GetUserInfo returns info for a given user. Like chat info, fields can be nil to skip them.
	GetUserInfo(ctx context.Context, ghost *Ghost) (*UserInfo, error)
	// GetCapabilities returns the bridging capabilities in a given room.
	// This can simply return a static list if the remote network has no per-chat capability differences,
	// but all calls will include the portal, because some networks do have per-chat differences.
	GetCapabilities(ctx context.Context, portal *Portal) *NetworkRoomCapabilities

	// HandleMatrixMessage is called when a message is sent from Matrix in an existing portal room.
	// This function should convert the message as appropriate, send it over to the remote network,
	// and return the info so the central bridge can store it in the database.
	//
	// This is only called for normal non-edit messages. For other types of events, see the optional extra interfaces (`XHandlingNetworkAPI`).
	HandleMatrixMessage(ctx context.Context, msg *MatrixMessage) (message *MatrixMessageResponse, err error)
}

// EditHandlingNetworkAPI is an optional interface that network connectors can implement to handle message edits.
type EditHandlingNetworkAPI interface {
	NetworkAPI
	// HandleMatrixEdit is called when a previously bridged message is edited in a portal room.
	// The central bridge module will save the [*database.Message] after this function returns,
	// so the network connector is allowed to mutate the provided object.
	HandleMatrixEdit(ctx context.Context, msg *MatrixEdit) error
}

// ReactionHandlingNetworkAPI is an optional interface that network connectors can implement to handle message reactions.
type ReactionHandlingNetworkAPI interface {
	NetworkAPI
	// PreHandleMatrixReaction is called as the first step of handling a reaction. It returns the emoji ID,
	// sender user ID and max reaction count to allow the central bridge module to de-duplicate the reaction
	// if appropriate.
	PreHandleMatrixReaction(ctx context.Context, msg *MatrixReaction) (MatrixReactionPreResponse, error)
	// HandleMatrixReaction is called after confirming that the reaction is not a duplicate.
	// This is the method that should actually send the reaction to the remote network.
	// The returned [database.Reaction] object may be empty: the central bridge module already has
	// all the required fields and will fill them automatically if they're empty. However, network
	// connectors are allowed to set fields themselves if any extra fields are necessary.
	HandleMatrixReaction(ctx context.Context, msg *MatrixReaction) (reaction *database.Reaction, err error)
	// HandleMatrixReactionRemove is called when a redaction event is received pointing at a previously
	// bridged reaction. The network connector should remove the reaction from the remote network.
	HandleMatrixReactionRemove(ctx context.Context, msg *MatrixReactionRemove) error
}

// RedactionHandlingNetworkAPI is an optional interface that network connectors can implement to handle message deletions.
type RedactionHandlingNetworkAPI interface {
	NetworkAPI
	// HandleMatrixMessageRemove is called when a previously bridged message is deleted in a portal room.
	HandleMatrixMessageRemove(ctx context.Context, msg *MatrixMessageRemove) error
}

// ReadReceiptHandlingNetworkAPI is an optional interface that network connectors can implement to handle read receipts.
type ReadReceiptHandlingNetworkAPI interface {
	NetworkAPI
	// HandleMatrixReadReceipt is called when a read receipt is sent in a portal room.
	// This will be called even if the target message is not a bridged message.
	// Network connectors must gracefully handle [MatrixReadReceipt.ExactMessage] being nil.
	// The exact handling is up to the network connector.
	HandleMatrixReadReceipt(ctx context.Context, msg *MatrixReadReceipt) error
}

// TypingHandlingNetworkAPI is an optional interface that network connectors can implement to handle typing events.
type TypingHandlingNetworkAPI interface {
	NetworkAPI
	// HandleMatrixTyping is called when a user starts typing in a portal room.
	// In the future, the central bridge module will likely get a loop to automatically repeat
	// calls to this function until the user stops typing.
	HandleMatrixTyping(ctx context.Context, msg *MatrixTyping) error
}

// RoomNameHandlingNetworkAPI is an optional interface that network connectors can implement to handle room name changes.
type RoomNameHandlingNetworkAPI interface {
	NetworkAPI
	// HandleMatrixRoomName is called when the name of a portal room is changed.
	// This method should update the Name and NameSet fields of the Portal with
	// the new name and return true if the change was successful.
	// If the change is not successful, then the fields should not be updated.
	HandleMatrixRoomName(ctx context.Context, msg *MatrixRoomName) (bool, error)
}

// RoomAvatarHandlingNetworkAPI is an optional interface that network connectors can implement to handle room avatar changes.
type RoomAvatarHandlingNetworkAPI interface {
	NetworkAPI
	// HandleMatrixRoomAvatar is called when the avatar of a portal room is changed.
	// This method should update the AvatarID, AvatarHash and AvatarMXC fields
	// with the new avatar details and return true if the change was successful.
	// If the change is not successful, then the fields should not be updated.
	HandleMatrixRoomAvatar(ctx context.Context, msg *MatrixRoomAvatar) (bool, error)
}

// RoomTopicHandlingNetworkAPI is an optional interface that network connectors can implement to handle room topic changes.
type RoomTopicHandlingNetworkAPI interface {
	NetworkAPI
	// HandleMatrixRoomTopic is called when the topic of a portal room is changed.
	// This method should update the Topic and TopicSet fields of the Portal with
	// the new topic and return true if the change was successful.
	// If the change is not successful, then the fields should not be updated.
	HandleMatrixRoomTopic(ctx context.Context, msg *MatrixRoomTopic) (bool, error)
}

type ResolveIdentifierResponse struct {
	// Ghost is the ghost of the user that the identifier resolves to.
	// This field should be set whenever possible. However, it is not required,
	// and the central bridge module will not try to create a ghost if it is not set.
	Ghost *Ghost

	// UserID is the user ID of the user that the identifier resolves to.
	UserID networkid.UserID
	// UserInfo contains the info of the user that the identifier resolves to.
	// If both this and the Ghost field are set, the central bridge module will
	// automatically update the ghost's info with the data here.
	UserInfo *UserInfo

	// Chat contains info about the direct chat with the resolved user.
	// This field is required when createChat is true in the ResolveIdentifier call,
	// and optional otherwise.
	Chat *CreateChatResponse
}

type CreateChatResponse struct {
	Portal *Portal

	PortalID   networkid.PortalKey
	PortalInfo *ChatInfo
}

// IdentifierResolvingNetworkAPI is an optional interface that network connectors can implement to support starting new direct chats.
type IdentifierResolvingNetworkAPI interface {
	NetworkAPI
	// ResolveIdentifier is called when the user wants to start a new chat.
	// This can happen via the `resolve-identifier` or `start-chat` bridge bot commands,
	// or the corresponding provisioning API endpoints.
	ResolveIdentifier(ctx context.Context, identifier string, createChat bool) (*ResolveIdentifierResponse, error)
}

// ContactListingNetworkAPI is an optional interface that network connectors can implement to provide the user's contact list.
type ContactListingNetworkAPI interface {
	NetworkAPI
	GetContactList(ctx context.Context) ([]*ResolveIdentifierResponse, error)
}

type UserSearchingNetworkAPI interface {
	IdentifierResolvingNetworkAPI
	SearchUsers(ctx context.Context, query string) ([]*ResolveIdentifierResponse, error)
}

type GroupCreatingNetworkAPI interface {
	IdentifierResolvingNetworkAPI
	CreateGroup(ctx context.Context, name string, users ...networkid.UserID) (*CreateChatResponse, error)
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
	RemoteEventMarkUnread
	RemoteEventTyping
	RemoteEventChatInfoChange
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

type RemotePreHandler interface {
	RemoteEvent
	PreHandle(ctx context.Context, portal *Portal)
}

type RemoteChatInfoChange interface {
	RemoteEvent
	GetChatInfoChange(ctx context.Context) (*ChatInfoChange, error)
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

type RemoteMarkUnread interface {
	RemoteEvent
	GetUnread() bool
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

type RoomMetaEventContent interface {
	*event.RoomNameEventContent | *event.RoomAvatarEventContent | *event.TopicEventContent
}

type MatrixRoomMeta[ContentType RoomMetaEventContent] struct {
	MatrixEventBase[ContentType]
	PrevContent ContentType
}

type MatrixRoomName = MatrixRoomMeta[*event.RoomNameEventContent]
type MatrixRoomAvatar = MatrixRoomMeta[*event.RoomAvatarEventContent]
type MatrixRoomTopic = MatrixRoomMeta[*event.TopicEventContent]

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
