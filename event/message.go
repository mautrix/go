// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event

import (
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"html"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"

	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/id"
)

// MessageType is the sub-type of a m.room.message event.
// https://spec.matrix.org/v1.2/client-server-api/#mroommessage-msgtypes
type MessageType string

func (mt MessageType) IsText() bool {
	switch mt {
	case MsgText, MsgNotice, MsgEmote:
		return true
	default:
		return false
	}
}

func (mt MessageType) IsMedia() bool {
	switch mt {
	case MsgImage, MsgVideo, MsgAudio, MsgFile, CapMsgSticker:
		return true
	default:
		return false
	}
}

// Msgtypes
const (
	MsgText     MessageType = "m.text"
	MsgEmote    MessageType = "m.emote"
	MsgNotice   MessageType = "m.notice"
	MsgImage    MessageType = "m.image"
	MsgLocation MessageType = "m.location"
	MsgVideo    MessageType = "m.video"
	MsgAudio    MessageType = "m.audio"
	MsgFile     MessageType = "m.file"

	MsgUnstableGallery MessageType = "dm.filament.gallery"

	MsgVerificationRequest MessageType = "m.key.verification.request"
)

// Format specifies the format of the formatted_body in m.room.message events.
// https://spec.matrix.org/v1.2/client-server-api/#mroommessage-msgtypes
type Format string

// Message formats
const (
	FormatHTML Format = "org.matrix.custom.html"
)

// RedactionEventContent represents the content of a m.room.redaction message event.
//
// https://spec.matrix.org/v1.8/client-server-api/#mroomredaction
type RedactionEventContent struct {
	Reason string `json:"reason,omitempty"`

	// The event ID is here as of room v11. In old servers it may only be at the top level.
	Redacts id.EventID `json:"redacts,omitempty"`

	DontRenderPlaceholder bool `json:"com.beeper.dont_render_redacted_placeholder,omitzero"`
}

// ReactionEventContent represents the content of a m.reaction message event.
// This is not yet in a spec release, see https://github.com/matrix-org/matrix-doc/pull/1849
type ReactionEventContent struct {
	RelatesTo RelatesTo `json:"m.relates_to"`
}

func (content *ReactionEventContent) GetRelatesTo() *RelatesTo {
	return &content.RelatesTo
}

func (content *ReactionEventContent) OptionalGetRelatesTo() *RelatesTo {
	return &content.RelatesTo
}

func (content *ReactionEventContent) SetRelatesTo(rel *RelatesTo) {
	content.RelatesTo = *rel
}

// MessageEventContent represents the content of a m.room.message event.
//
// It is also used to represent m.sticker events, as they are equivalent to m.room.message
// with the exception of the msgtype field.
//
// https://spec.matrix.org/v1.2/client-server-api/#mroommessage
type MessageEventContent struct {
	// Base m.room.message fields
	MsgType MessageType `json:"msgtype,omitempty"`
	Body    string      `json:"body"`

	// Extra fields for text types
	Format        Format `json:"format,omitempty"`
	FormattedBody string `json:"formatted_body,omitempty"`

	// Extra field for m.location
	GeoURI string `json:"geo_uri,omitempty"`

	// Extra fields for media types
	URL      id.ContentURIString `json:"url,omitempty"`
	Info     *FileInfo           `json:"info,omitzero"`
	File     *EncryptedFileInfo  `json:"file,omitzero"`
	FileName string              `json:"filename,omitempty"`

	UnstableGalleryItemType MessageType            `json:"itemtype,omitempty"`
	UnstableGalleryItems    []*MessageEventContent `json:"itemtypes,omitempty"`
	GalleryItems            []*MessageEventContent `json:"items,omitempty"`

	// Edits and relations
	NewContent *MessageEventContent `json:"m.new_content,omitzero"`
	RelatesTo  *RelatesTo           `json:"m.relates_to,omitzero"`
	Mentions   *Mentions            `json:"m.mentions,omitzero"`

	replyFallbackRemoved bool

	// In-room verification
	To         id.UserID            `json:"to,omitempty"`
	FromDevice id.DeviceID          `json:"from_device,omitempty"`
	Methods    []VerificationMethod `json:"methods,omitempty"`

	ImageSourcePacks map[id.ContentURIString]*ImageSource    `json:"com.beeper.msc4459.image_source_packs,omitempty"`
	BridgedEmojis    map[id.ContentURIString]*BridgedSticker `json:"com.beeper.bridged_emojis,omitempty"`

	MessageSendRetry             *BeeperRetryMetadata     `json:"com.beeper.message_send_retry,omitzero"`
	BeeperPerMessageProfile      *BeeperPerMessageProfile `json:"com.beeper.per_message_profile,omitzero"`
	BeeperActionMessage          *BeeperActionMessage     `json:"com.beeper.action_message,omitzero"`
	BeeperLinkPreviews           []*BeeperLinkPreview     `json:"com.beeper.linkpreviews,omitzero"`
	BeeperStream                 *BeeperStreamInfo        `json:"com.beeper.stream,omitzero"`
	BeeperDisappearingTimer      *BeeperDisappearingTimer `json:"com.beeper.disappearing_timer,omitzero"`
	BeeperViewLimited            *BeeperViewLimitedMedia  `json:"com.beeper.view_limited,omitzero"`
	BeeperBroadcastOutsideThread bool                     `json:"com.beeper.broadcast_outside_thread,omitzero"`

	MSC1767Audio *MSC1767Audio `json:"org.matrix.msc1767.audio,omitzero"`
	MSC3245Voice *MSC3245Voice `json:"org.matrix.msc3245.voice,omitzero"`

	MSC4391BotCommand *MSC4391BotCommandInput `json:"org.matrix.msc4391.command,omitempty"`
}

func (content *MessageEventContent) GetCapMsgType() CapabilityMsgType {
	switch content.MsgType {
	case CapMsgSticker:
		return CapMsgSticker
	case "":
		if content.URL != "" || content.File != nil {
			return CapMsgSticker
		}
	case MsgImage:
		return MsgImage
	case MsgAudio:
		if content.MSC3245Voice != nil {
			return CapMsgVoice
		}
		return MsgAudio
	case MsgVideo:
		if content.Info != nil && content.Info.MauGIF {
			return CapMsgGIF
		}
		return MsgVideo
	case MsgFile:
		return MsgFile
	}
	return ""
}

func (content *MessageEventContent) GetFileName() string {
	if content.FileName != "" {
		return content.FileName
	}
	return content.Body
}

func (content *MessageEventContent) GetCaption() string {
	if content.FileName != "" && content.Body != "" && content.Body != content.FileName {
		return content.Body
	}
	return ""
}

func (content *MessageEventContent) GetFormattedCaption() string {
	if content.Format == FormatHTML && content.FormattedBody != "" {
		return content.FormattedBody
	}
	return ""
}

func (content *MessageEventContent) GetRelatesTo() *RelatesTo {
	if content.RelatesTo == nil {
		content.RelatesTo = &RelatesTo{}
	}
	return content.RelatesTo
}

func (content *MessageEventContent) OptionalGetRelatesTo() *RelatesTo {
	return content.RelatesTo
}

func (content *MessageEventContent) SetRelatesTo(rel *RelatesTo) {
	content.RelatesTo = rel
}

func (content *MessageEventContent) SetEdit(original id.EventID) {
	newContent := *content
	*content = MessageEventContent{
		MsgType:    content.MsgType,
		Body:       content.Body,
		GeoURI:     content.GeoURI,
		URL:        content.URL,
		File:       content.File,
		FileName:   content.FileName,
		Mentions:   &Mentions{},
		NewContent: &newContent,
		RelatesTo:  (&RelatesTo{}).SetReplace(original),
	}
	if content.MsgType == MsgText || content.MsgType == MsgNotice {
		content.Body = "* " + content.Body
	}
	if len(content.Body) > 100 {
		content.Body = content.Body[:min(len(content.Body), 50)] + "[edit fallback cut…]"
	}
}

// TextToHTML converts the given text to a HTML-safe representation by escaping HTML characters
// and replacing newlines with <br/> tags.
func TextToHTML(text string) string {
	return strings.ReplaceAll(html.EscapeString(text), "\n", "<br/>")
}

// ReverseTextToHTML reverses the modifications made by TextToHTML, i.e. replaces <br/> tags with newlines
// and unescapes HTML escape codes. For actually parsing HTML, use the format package instead.
func ReverseTextToHTML(input string) string {
	return html.UnescapeString(strings.ReplaceAll(input, "<br/>", "\n"))
}

func (content *MessageEventContent) EnsureHasHTML() {
	if content.MsgType.IsMedia() && (content.FileName == "" || content.FileName == content.Body) {
		content.FileName = content.Body
		content.Body = ""
	}
	if len(content.FormattedBody) == 0 || content.Format != FormatHTML {
		content.FormattedBody = TextToHTML(content.Body)
		content.Format = FormatHTML
	}
}

func (content *MessageEventContent) GetFile() *EncryptedFileInfo {
	if content.File == nil {
		content.File = &EncryptedFileInfo{}
	}
	return content.File
}

func (content *MessageEventContent) GetInfo() *FileInfo {
	if content.Info == nil {
		content.Info = &FileInfo{}
	}
	return content.Info
}

type Mentions struct {
	UserIDs []id.UserID `json:"user_ids,omitempty"`
	Room    bool        `json:"room,omitzero"`
}

func (m *Mentions) Add(userID id.UserID) {
	if userID != "" && !slices.Contains(m.UserIDs, userID) {
		m.UserIDs = append(m.UserIDs, userID)
	}
}

func (m *Mentions) Has(userID id.UserID) bool {
	return m != nil && slices.Contains(m.UserIDs, userID)
}

func (m *Mentions) Merge(other *Mentions) *Mentions {
	if m == nil {
		return other
	} else if other == nil {
		return m
	}
	return &Mentions{
		UserIDs: slices.Concat(m.UserIDs, other.UserIDs),
		Room:    m.Room || other.Room,
	}
}

type MSC4391BotCommandInputCustom[T any] struct {
	Command   string `json:"command"`
	Arguments T      `json:"arguments,omitempty"`
}

type MSC4391BotCommandInput = MSC4391BotCommandInputCustom[jsontext.Value]

type EncryptedFileInfo struct {
	attachment.EncryptedFile
	URL id.ContentURIString `json:"url"`
}

type FileInfo struct {
	MimeType      string
	ThumbnailInfo *FileInfo
	ThumbnailURL  id.ContentURIString
	ThumbnailFile *EncryptedFileInfo

	Blurhash     string
	AnoaBlurhash string

	MauGIF     bool
	IsAnimated bool

	Width    int
	Height   int
	Duration int
	Size     int

	BridgedSticker *BridgedSticker

	Extra map[string]any
}

type serializableFileInfo struct {
	MimeType      string                `json:"mimetype,omitempty"`
	ThumbnailInfo *serializableFileInfo `json:"thumbnail_info,omitzero"`
	ThumbnailURL  id.ContentURIString   `json:"thumbnail_url,omitempty"`
	ThumbnailFile *EncryptedFileInfo    `json:"thumbnail_file,omitzero"`

	Blurhash     string `json:"blurhash,omitempty"`
	AnoaBlurhash string `json:"xyz.amorgan.blurhash,omitempty"`

	MauGIF     bool `json:"fi.mau.gif,omitzero"`
	IsAnimated bool `json:"is_animated,omitzero"`

	Width    jsonv1.Number `json:"w,omitempty,omitzero"`
	Height   jsonv1.Number `json:"h,omitempty,omitzero"`
	Duration jsonv1.Number `json:"duration,omitempty,omitzero"`
	Size     jsonv1.Number `json:"size,omitempty,omitzero"`

	BridgedSticker *BridgedSticker `json:"fi.mau.bridged_sticker,omitzero"`

	Extra map[string]any `json:",embed,unknown"`
}

func (fileInfo *FileInfo) IsZero() bool {
	return fileInfo.MimeType == "" &&
		fileInfo.ThumbnailInfo == nil &&
		fileInfo.ThumbnailURL == "" &&
		fileInfo.ThumbnailFile == nil &&
		fileInfo.Blurhash == "" &&
		fileInfo.AnoaBlurhash == "" &&
		!fileInfo.MauGIF &&
		!fileInfo.IsAnimated &&
		fileInfo.Width == 0 &&
		fileInfo.Height == 0 &&
		fileInfo.Duration == 0 &&
		fileInfo.Size == 0 &&
		fileInfo.BridgedSticker == nil &&
		len(fileInfo.Extra) == 0
}

func (sfi *serializableFileInfo) CopyFrom(fileInfo *FileInfo) *serializableFileInfo {
	if fileInfo == nil {
		return nil
	}
	*sfi = serializableFileInfo{
		MimeType:      fileInfo.MimeType,
		ThumbnailURL:  fileInfo.ThumbnailURL,
		ThumbnailInfo: (&serializableFileInfo{}).CopyFrom(fileInfo.ThumbnailInfo),
		ThumbnailFile: fileInfo.ThumbnailFile,

		MauGIF:     fileInfo.MauGIF,
		IsAnimated: fileInfo.IsAnimated,

		Blurhash:     fileInfo.Blurhash,
		AnoaBlurhash: fileInfo.AnoaBlurhash,

		BridgedSticker: fileInfo.BridgedSticker,

		Extra: withoutStandardFileInfoFields(fileInfo.Extra),
	}
	if fileInfo.Width > 0 {
		sfi.Width = jsonv1.Number(strconv.Itoa(fileInfo.Width))
	}
	if fileInfo.Height > 0 {
		sfi.Height = jsonv1.Number(strconv.Itoa(fileInfo.Height))
	}
	if fileInfo.Size > 0 {
		sfi.Size = jsonv1.Number(strconv.Itoa(fileInfo.Size))

	}
	if fileInfo.Duration > 0 {
		sfi.Duration = jsonv1.Number(strconv.Itoa(int(fileInfo.Duration)))
	}
	return sfi
}

func (sfi *serializableFileInfo) CopyTo(fileInfo *FileInfo) {
	*fileInfo = FileInfo{
		Width:          numberToInt(sfi.Width),
		Height:         numberToInt(sfi.Height),
		Size:           numberToInt(sfi.Size),
		Duration:       numberToInt(sfi.Duration),
		MimeType:       sfi.MimeType,
		ThumbnailURL:   sfi.ThumbnailURL,
		ThumbnailFile:  sfi.ThumbnailFile,
		MauGIF:         sfi.MauGIF,
		IsAnimated:     sfi.IsAnimated,
		Blurhash:       sfi.Blurhash,
		AnoaBlurhash:   sfi.AnoaBlurhash,
		BridgedSticker: sfi.BridgedSticker,

		Extra: sfi.Extra,
	}
	if sfi.ThumbnailInfo != nil {
		fileInfo.ThumbnailInfo = &FileInfo{}
		sfi.ThumbnailInfo.CopyTo(fileInfo.ThumbnailInfo)
	}
}

var standardFileInfoFields = []string{
	"mimetype", "thumbnail_info", "thumbnail_url", "thumbnail_file", "blurhash", "xyz.amorgan.blurhash",
	"fi.mau.gif", "is_animated", "w", "h", "duration", "size", "fi.mau.bridged_sticker",
}

func withoutStandardFileInfoFields(extra map[string]any) map[string]any {
	for _, field := range standardFileInfoFields {
		if _, found := extra[field]; found {
			extra = maps.Clone(extra)
			for _, field = range standardFileInfoFields {
				delete(extra, field)
			}
			break
		}
	}
	return extra
}

func (fileInfo *FileInfo) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var sfi serializableFileInfo
	if err := json.UnmarshalDecode(dec, &sfi); err != nil {
		return err
	}
	sfi.CopyTo(fileInfo)
	return nil
}

func (fileInfo *FileInfo) MarshalJSONTo(enc *jsontext.Encoder) error {
	return json.MarshalEncode(enc, (&serializableFileInfo{}).CopyFrom(fileInfo))
}

func numberToInt(val jsonv1.Number) int {
	f64, _ := val.Float64()
	if f64 > 0 {
		return int(f64)
	}
	return 0
}

func (fileInfo *FileInfo) GetThumbnailInfo() *FileInfo {
	if fileInfo.ThumbnailInfo == nil {
		fileInfo.ThumbnailInfo = &FileInfo{}
	}
	return fileInfo.ThumbnailInfo
}
