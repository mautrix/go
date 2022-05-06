package mautrix

import (
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// RespWhoami is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3accountwhoami
type RespWhoami struct {
	UserID   id.UserID   `json:"user_id"`
	DeviceID id.DeviceID `json:"device_id"`
}

// RespCreateFilter is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3useruseridfilter
type RespCreateFilter struct {
	FilterID string `json:"filter_id"`
}

// RespJoinRoom is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3roomsroomidjoin
type RespJoinRoom struct {
	RoomID id.RoomID `json:"room_id"`
}

// RespLeaveRoom is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3roomsroomidleave
type RespLeaveRoom struct{}

// RespForgetRoom is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3roomsroomidforget
type RespForgetRoom struct{}

// RespInviteUser is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3roomsroomidinvite
type RespInviteUser struct{}

// RespKickUser is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3roomsroomidkick
type RespKickUser struct{}

// RespBanUser is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3roomsroomidban
type RespBanUser struct{}

// RespUnbanUser is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3roomsroomidunban
type RespUnbanUser struct{}

// RespTyping is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#put_matrixclientv3roomsroomidtypinguserid
type RespTyping struct{}

// RespPresence is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3presenceuseridstatus
type RespPresence struct {
	Presence        event.Presence `json:"presence"`
	LastActiveAgo   int            `json:"last_active_ago"`
	StatusMsg       string         `json:"status_msg"`
	CurrentlyActive bool           `json:"currently_active"`
}

// RespJoinedRooms is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3joined_rooms
type RespJoinedRooms struct {
	JoinedRooms []id.RoomID `json:"joined_rooms"`
}

// RespJoinedMembers is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3roomsroomidjoined_members
type RespJoinedMembers struct {
	Joined map[id.UserID]struct {
		DisplayName *string `json:"display_name"`
		AvatarURL   *string `json:"avatar_url"`
	} `json:"joined"`
}

// RespMessages is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3roomsroomidmessages
type RespMessages struct {
	Start string         `json:"start"`
	Chunk []*event.Event `json:"chunk"`
	State []*event.Event `json:"state"`
	End   string         `json:"end"`
}

// RespContext is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3roomsroomidcontexteventid
type RespContext struct {
	End          string         `json:"end"`
	Event        *event.Event   `json:"event"`
	EventsAfter  []*event.Event `json:"events_after"`
	EventsBefore []*event.Event `json:"events_before"`
	Start        string         `json:"start"`
	State        []*event.Event `json:"state"`
}

// RespSendEvent is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid
type RespSendEvent struct {
	EventID id.EventID `json:"event_id"`
}

// RespMediaUpload is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixmediav3upload
type RespMediaUpload struct {
	ContentURI id.ContentURI `json:"content_uri"`
}

// RespCreateMXC is the JSON response for /_matrix/media/v3/create as specified in https://github.com/matrix-org/matrix-spec-proposals/pull/2246
type RespCreateMXC struct {
	ContentURI      id.ContentURI `json:"content_uri"`
	UnusedExpiresAt int           `json:"unused_expires_at,omitempty"`
}

// RespPreviewURL is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixmediav3preview_url
type RespPreviewURL struct {
	CanonicalURL string `json:"og:url,omitempty"`
	Title        string `json:"og:title,omitempty"`
	Type         string `json:"og:type,omitempty"`
	Description  string `json:"og:description,omitempty"`

	ImageURL id.ContentURIString `json:"og:image,omitempty"`

	ImageSize   int    `json:"matrix:image:size,omitempty"`
	ImageWidth  int    `json:"og:image:width,omitempty"`
	ImageHeight int    `json:"og:image:height,omitempty"`
	ImageType   string `json:"og:image:type,omitempty"`
}

// RespUserInteractive is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#user-interactive-authentication-api
type RespUserInteractive struct {
	Flows []struct {
		Stages []AuthType `json:"stages"`
	} `json:"flows"`
	Params    map[AuthType]interface{} `json:"params"`
	Session   string                   `json:"session"`
	Completed []string                 `json:"completed"`

	ErrCode string `json:"errcode"`
	Error   string `json:"error"`
}

// HasSingleStageFlow returns true if there exists at least 1 Flow with a single stage of stageName.
func (r RespUserInteractive) HasSingleStageFlow(stageName AuthType) bool {
	for _, f := range r.Flows {
		if len(f.Stages) == 1 && f.Stages[0] == stageName {
			return true
		}
	}
	return false
}

// RespUserDisplayName is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3profileuseriddisplayname
type RespUserDisplayName struct {
	DisplayName string `json:"displayname"`
}

// RespRegister is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3register
type RespRegister struct {
	AccessToken  string      `json:"access_token"`
	DeviceID     id.DeviceID `json:"device_id"`
	HomeServer   string      `json:"home_server"`
	RefreshToken string      `json:"refresh_token"`
	UserID       id.UserID   `json:"user_id"`
}

type LoginFlow struct {
	Type AuthType `json:"type"`
}

// RespLoginFlows is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3login
type RespLoginFlows struct {
	Flows []LoginFlow `json:"flows"`
}

func (rlf *RespLoginFlows) FirstFlowOfType(flowTypes ...AuthType) *LoginFlow {
	for _, flow := range rlf.Flows {
		for _, flowType := range flowTypes {
			if flow.Type == flowType {
				return &flow
			}
		}
	}
	return nil
}

func (rlf *RespLoginFlows) HasFlow(flowType ...AuthType) bool {
	return rlf.FirstFlowOfType(flowType...) != nil
}

// RespLogin is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3login
type RespLogin struct {
	AccessToken string           `json:"access_token"`
	DeviceID    id.DeviceID      `json:"device_id"`
	UserID      id.UserID        `json:"user_id"`
	WellKnown   *ClientWellKnown `json:"well_known"`
}

// RespLogout is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3logout
type RespLogout struct{}

// RespCreateRoom is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3createroom
type RespCreateRoom struct {
	RoomID id.RoomID `json:"room_id"`
}

type RespMembers struct {
	Chunk []*event.Event `json:"chunk"`
}

type LazyLoadSummary struct {
	Heroes             []id.UserID `json:"m.heroes,omitempty"`
	JoinedMemberCount  *int        `json:"m.joined_member_count,omitempty"`
	InvitedMemberCount *int        `json:"m.invited_member_count,omitempty"`
}

// RespSync is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3sync
type RespSync struct {
	NextBatch string `json:"next_batch"`

	AccountData struct {
		Events []*event.Event `json:"events"`
	} `json:"account_data"`
	Presence struct {
		Events []*event.Event `json:"events"`
	} `json:"presence"`
	ToDevice struct {
		Events []*event.Event `json:"events"`
	} `json:"to_device"`

	DeviceLists    DeviceLists `json:"device_lists"`
	DeviceOTKCount OTKCount    `json:"device_one_time_keys_count"`

	Rooms struct {
		Leave  map[id.RoomID]SyncLeftRoom    `json:"leave"`
		Join   map[id.RoomID]SyncJoinedRoom  `json:"join"`
		Invite map[id.RoomID]SyncInvitedRoom `json:"invite"`
	} `json:"rooms"`
}

type DeviceLists struct {
	Changed []id.UserID `json:"changed"`
	Left    []id.UserID `json:"left"`
}

type OTKCount struct {
	Curve25519       int `json:"curve25519"`
	SignedCurve25519 int `json:"signed_curve25519"`

	// For appservice OTK counts only: the user ID in question
	UserID   id.UserID   `json:"-"`
	DeviceID id.DeviceID `json:"-"`
}

type SyncLeftRoom struct {
	Summary LazyLoadSummary `json:"summary"`
	State   struct {
		Events []*event.Event `json:"events"`
	} `json:"state"`
	Timeline struct {
		Events    []*event.Event `json:"events"`
		Limited   bool           `json:"limited"`
		PrevBatch string         `json:"prev_batch"`
	} `json:"timeline"`
}

type SyncJoinedRoom struct {
	Summary LazyLoadSummary `json:"summary"`
	State   struct {
		Events []*event.Event `json:"events"`
	} `json:"state"`
	Timeline struct {
		Events    []*event.Event `json:"events"`
		Limited   bool           `json:"limited"`
		PrevBatch string         `json:"prev_batch"`
	} `json:"timeline"`
	Ephemeral struct {
		Events []*event.Event `json:"events"`
	} `json:"ephemeral"`
	AccountData struct {
		Events []*event.Event `json:"events"`
	} `json:"account_data"`
}

type SyncInvitedRoom struct {
	Summary LazyLoadSummary `json:"summary"`
	State   struct {
		Events []*event.Event `json:"events"`
	} `json:"invite_state"`
}

type RespTurnServer struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	TTL      int      `json:"ttl"`
	URIs     []string `json:"uris"`
}

type RespAliasCreate struct{}
type RespAliasDelete struct{}
type RespAliasResolve struct {
	RoomID  id.RoomID `json:"room_id"`
	Servers []string  `json:"servers"`
}
type RespAliasList struct {
	Aliases []id.RoomAlias `json:"aliases"`
}

type RespUploadKeys struct {
	OneTimeKeyCounts OTKCount `json:"one_time_key_counts"`
}

type RespQueryKeys struct {
	Failures        map[string]interface{}                   `json:"failures"`
	DeviceKeys      map[id.UserID]map[id.DeviceID]DeviceKeys `json:"device_keys"`
	MasterKeys      map[id.UserID]CrossSigningKeys           `json:"master_keys"`
	SelfSigningKeys map[id.UserID]CrossSigningKeys           `json:"self_signing_keys"`
	UserSigningKeys map[id.UserID]CrossSigningKeys           `json:"user_signing_keys"`
}

type RespClaimKeys struct {
	Failures    map[string]interface{}                                `json:"failures"`
	OneTimeKeys map[id.UserID]map[id.DeviceID]map[id.KeyID]OneTimeKey `json:"one_time_keys"`
}

type RespUploadSignatures struct {
	Failures map[string]interface{} `json:"failures"`
}

type RespKeyChanges struct {
	Changed []id.UserID `json:"changed"`
	Left    []id.UserID `json:"left"`
}

type RespSendToDevice struct{}

// RespDevicesInfo is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3devices
type RespDevicesInfo struct {
	Devices []RespDeviceInfo `json:"devices"`
}

// RespDeviceInfo is the JSON response for https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3devicesdeviceid
type RespDeviceInfo struct {
	DeviceID    id.DeviceID `json:"device_id"`
	DisplayName string      `json:"display_name"`
	LastSeenIP  string      `json:"last_seen_ip"`
	LastSeenTS  int64       `json:"last_seen_ts"`
}

type RespBatchSend struct {
	StateEventIDs []id.EventID `json:"state_event_ids"`
	EventIDs      []id.EventID `json:"event_ids"`

	InsertionEventID     id.EventID `json:"insertion_event_id"`
	BatchEventID         id.EventID `json:"batch_event_id"`
	BaseInsertionEventID id.EventID `json:"base_insertion_event_id"`

	NextBatchID id.BatchID `json:"next_batch_id"`
}
