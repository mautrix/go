// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package eventauth

import (
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
	"go.mau.fi/util/exgjson"
	"go.mau.fi/util/exstrings"
	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/federation/signutil"
	"maunium.net/go/mautrix/id"
)

type AuthFailError struct {
	Index   string
	Message string
	Wrapped error
}

func (afe AuthFailError) Error() string {
	if afe.Message != "" {
		return fmt.Sprintf("fail %s: %s", afe.Index, afe.Message)
	} else if afe.Wrapped != nil {
		return fmt.Sprintf("fail %s: %s", afe.Index, afe.Wrapped.Error())
	}
	return fmt.Sprintf("fail %s", afe.Index)
}

func (afe AuthFailError) Unwrap() error {
	return afe.Wrapped
}

var mFederatePath = exgjson.Path("m.federate")

var (
	ErrCreateHasPrevEvents       = AuthFailError{Index: "1.1", Message: "m.room.create event has prev_events"}
	ErrCreateHasRoomID           = AuthFailError{Index: "1.2", Message: "m.room.create event has room_id set"}
	ErrRoomIDDoesntMatchSender   = AuthFailError{Index: "1.2", Message: "room ID server doesn't match sender server"}
	ErrUnknownRoomVersion        = AuthFailError{Index: "1.3", Wrapped: id.ErrUnknownRoomVersion}
	ErrInvalidAdditionalCreators = AuthFailError{Index: "1.4", Message: "m.room.create event has invalid additional_creators"}
	ErrMissingCreator            = AuthFailError{Index: "1.4", Message: "m.room.create event is missing creator field"}

	ErrInvalidRoomIDLength    = AuthFailError{Index: "2", Message: "room ID length is invalid"}
	ErrFailedToGetCreateEvent = AuthFailError{Index: "2", Message: "failed to get m.room.create event"}
	ErrCreateEventNotFound    = AuthFailError{Index: "2", Message: "m.room.create event not found using room ID as event ID"}
	ErrRejectedCreateEvent    = AuthFailError{Index: "2", Message: "m.room.create event was rejected"}

	ErrFailedToGetAuthEvents        = AuthFailError{Index: "3", Message: "failed to get auth events"}
	ErrFailedToParsePowerLevels     = AuthFailError{Index: "?", Message: "failed to parse power levels"}
	ErrDuplicateAuthEvent           = AuthFailError{Index: "3.1", Message: "duplicate type/state key pair in auth events"}
	ErrNonStateAuthEvent            = AuthFailError{Index: "3.2", Message: "non-state event in auth events"}
	ErrMissingAuthEvent             = AuthFailError{Index: "3.2", Message: "missing auth event"}
	ErrUnexpectedAuthEvent          = AuthFailError{Index: "3.2", Message: "unexpected type/state key pair in auth events"}
	ErrNoCreateEvent                = AuthFailError{Index: "3.2", Message: "no m.room.create event found in auth events"}
	ErrRejectedAuthEvent            = AuthFailError{Index: "3.3", Message: "auth event was rejected"}
	ErrMismatchingRoomIDInAuthEvent = AuthFailError{Index: "3.4", Message: "auth event room ID does not match event room ID"}

	ErrFederationDisabled = AuthFailError{Index: "4", Message: "federation is disabled for this room"}

	ErrMemberNotState                  = AuthFailError{Index: "5.1", Message: "m.room.member event is not a state event"}
	ErrNotSignedByAuthoriser           = AuthFailError{Index: "5.2", Message: "m.room.member event is not signed by server of join_authorised_via_users_server"}
	ErrCantJoinOtherUser               = AuthFailError{Index: "5.3.2", Message: "can't send join event with different state key"}
	ErrCantJoinBanned                  = AuthFailError{Index: "5.3.3", Message: "user is banned from the room"}
	ErrAuthoriserCantInvite            = AuthFailError{Index: "5.3.5.2", Message: "authoriser doesn't have sufficient power level to invite"}
	ErrAuthoriserNotInRoom             = AuthFailError{Index: "5.3.5.2", Message: "authoriser isn't a member of the room"}
	ErrCantJoinWithoutInvite           = AuthFailError{Index: "5.3.7", Message: "can't join invite-only room without invite"}
	ErrInvalidJoinRule                 = AuthFailError{Index: "5.3.7", Message: "invalid join rule in room"}
	ErrThirdPartyInviteBanned          = AuthFailError{Index: "5.4.1.1", Message: "third party invite target user is banned"}
	ErrThirdPartyInviteMissingFields   = AuthFailError{Index: "5.4.1.3", Message: "third party invite is missing mxid or token fields"}
	ErrThirdPartyInviteMXIDMismatch    = AuthFailError{Index: "5.4.1.4", Message: "mxid in signed third party invite doesn't match event state key"}
	ErrThirdPartyInviteNotFound        = AuthFailError{Index: "5.4.1.5", Message: "matching m.room.third_party_invite event not found in auth events"}
	ErrThirdPartyInviteSenderMismatch  = AuthFailError{Index: "5.4.1.6", Message: "sender of third party invite doesn't match sender of member event"}
	ErrThirdPartyInviteNotSigned       = AuthFailError{Index: "5.4.1.8", Message: "no valid signatures found for third party invite"}
	ErrInviterNotInRoom                = AuthFailError{Index: "5.4.2", Message: "inviter's membership is not join"}
	ErrInviteTargetAlreadyInRoom       = AuthFailError{Index: "5.4.3", Message: "invite target user is already in the room"}
	ErrInviteTargetBanned              = AuthFailError{Index: "5.4.3", Message: "invite target user is banned"}
	ErrInsufficientPermissionForInvite = AuthFailError{Index: "5.4.5", Message: "inviter does not have sufficient permission to send invites"}
	ErrCantLeaveWithoutBeingInRoom     = AuthFailError{Index: "5.5.1", Message: "can't leave room without being in it"}
	ErrCantKickWithoutBeingInRoom      = AuthFailError{Index: "5.5.2", Message: "can't kick another user without being in the room"}
	ErrInsufficientPermissionForUnban  = AuthFailError{Index: "5.5.3", Message: "sender does not have sufficient permission to unban users"}
	ErrInsufficientPermissionForKick   = AuthFailError{Index: "5.5.5", Message: "sender does not have sufficient permission to kick the user"}
	ErrCantBanWithoutBeingInRoom       = AuthFailError{Index: "5.6.1", Message: "can't ban another user without being in the room"}
	ErrInsufficientPermissionForBan    = AuthFailError{Index: "5.6.3", Message: "sender does not have sufficient permission to ban the user"}
	ErrNotKnockableRoom                = AuthFailError{Index: "5.7.1", Message: "join rule doesn't allow knocking"}
	ErrCantKnockOtherUser              = AuthFailError{Index: "5.7.1", Message: "can't send knock event with different state key"}
	ErrCantKnockWhileInRoom            = AuthFailError{Index: "5.7.2", Message: "can't knock while joined, invited or banned"}
	ErrUnknownMembership               = AuthFailError{Index: "5.8", Message: "unknown membership in m.room.member event"}

	ErrNotInRoom = AuthFailError{Index: "6", Message: "sender is not a member of the room"}

	ErrInsufficientPowerForThirdPartyInvite = AuthFailError{Index: "7.1", Message: "sender does not have sufficient power level to send third party invite"}

	ErrInsufficientPowerLevel = AuthFailError{Index: "8", Message: "sender does not have sufficient power level to send event"}

	ErrMismatchingPrivateStateKey = AuthFailError{Index: "9", Message: "state keys starting with @ must match sender user ID"}

	ErrTopLevelPLNotInteger   = AuthFailError{Index: "10.1", Message: "invalid type for top-level power level field"}
	ErrPLNotInteger           = AuthFailError{Index: "10.2", Message: "invalid type for power level"}
	ErrInvalidUserIDInPL      = AuthFailError{Index: "10.3", Message: "invalid user ID in power levels"}
	ErrUserPLNotInteger       = AuthFailError{Index: "10.3", Message: "invalid type for user power level"}
	ErrCreatorInPowerLevels   = AuthFailError{Index: "10.4", Message: "room creators must not be specified in power levels"}
	ErrInvalidPowerChange     = AuthFailError{Index: "10.x", Message: "illegal power level change"}
	ErrInvalidUserPowerChange = AuthFailError{Index: "10.9", Message: "illegal power level change"}
)

func isRejected(evt *pdu.PDU) bool {
	return evt.InternalMeta.Rejected
}

type GetEventsFunc = func(ids []id.EventID) ([]*pdu.PDU, error)

func Authorize(roomVersion id.RoomVersion, evt *pdu.PDU, getEvents GetEventsFunc, getKey pdu.GetKeyFunc) error {
	if evt.Type == event.StateCreate.Type {
		// 1. If type is m.room.create:
		return authorizeCreate(roomVersion, evt)
	}
	var createEvt *pdu.PDU
	if roomVersion.RoomIDIsCreateEventID() {
		// 2. If the event’s room_id is not an event ID for an accepted (not rejected) m.room.create event,
		//    with the sigil ! instead of $, reject.
		if len(evt.RoomID) != 44 {
			return fmt.Errorf("%w (%d)", ErrInvalidRoomIDLength, len(evt.RoomID))
		} else if createEvts, err := getEvents([]id.EventID{id.EventID("$" + evt.RoomID[1:])}); err != nil {
			return fmt.Errorf("%w: %w", ErrFailedToGetCreateEvent, err)
		} else if len(createEvts) != 1 {
			return fmt.Errorf("%w (%s)", ErrCreateEventNotFound, evt.RoomID)
		} else if isRejected(createEvts[0]) {
			return ErrRejectedCreateEvent
		} else {
			createEvt = createEvts[0]
		}
	}
	authEvents, err := getEvents(evt.AuthEvents)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedToGetAuthEvents, err)
	}
	expectedAuthEvents := evt.AuthEventSelection(roomVersion)
	deduplicator := make(map[pdu.StateKey]id.EventID, len(expectedAuthEvents))
	// 3. Considering the event’s auth_events:
	for i, ae := range authEvents {
		authEvtID := evt.AuthEvents[i]
		if ae == nil {
			return fmt.Errorf("%w (%s)", ErrMissingAuthEvent, authEvtID)
		} else if ae.StateKey == nil {
			// This approximately falls under rule 3.2.
			return fmt.Errorf("%w (%s)", ErrNonStateAuthEvent, authEvtID)
		}
		key := pdu.StateKey{Type: ae.Type, StateKey: *ae.StateKey}
		if prevEvtID, alreadyFound := deduplicator[key]; alreadyFound {
			// 3.1. If there are duplicate entries for a given type and state_key pair, reject.
			return fmt.Errorf("%w for %s/%s: found %s and %s", ErrDuplicateAuthEvent, ae.Type, *ae.StateKey, prevEvtID, authEvtID)
		} else if !expectedAuthEvents.Has(key) {
			// 3.2. If there are entries whose type and state_key don’t match those specified by
			//      the auth events selection algorithm described in the server specification, reject.
			return fmt.Errorf("%w: found %s with key %s/%s", ErrUnexpectedAuthEvent, authEvtID, ae.Type, *ae.StateKey)
		} else if isRejected(ae) {
			// 3.3. If there are entries which were themselves rejected under the checks performed on receipt of a PDU, reject.
			return fmt.Errorf("%w (%s)", ErrRejectedAuthEvent, authEvtID)
		} else if ae.RoomID != evt.RoomID {
			// 3.4. If any event in auth_events has a room_id which does not match that of the event being authorised, reject.
			return fmt.Errorf("%w (%s)", ErrMismatchingRoomIDInAuthEvent, authEvtID)
		} else {
			deduplicator[key] = authEvtID
		}
		if ae.Type == event.StateCreate.Type {
			if createEvt == nil {
				createEvt = ae
			} else {
				// Duplicates are prevented by deduplicator, AuthEventSelection also won't allow a create event at all for v12+
				panic(fmt.Errorf("impossible case: multiple create events found in auth events"))
			}
		}
	}
	if createEvt == nil {
		// This comes either from auth_events or room_id depending on the room version.
		// The checks above make sure it's from the right source.
		return ErrNoCreateEvent
	}
	if federateVal := gjson.GetBytes(createEvt.Content, mFederatePath); federateVal.Type == gjson.False && createEvt.Sender.Homeserver() != evt.Sender.Homeserver() {
		// 4. If the content of the m.room.create event in the room state has the property m.federate set to false,
		//    and the sender domain of the event does not match the sender domain of the create event, reject.
		return ErrFederationDisabled
	}
	if evt.Type == event.StateMember.Type {
		// 5. If type is m.room.member:
		return authorizeMember(roomVersion, evt, createEvt, authEvents, getKey)
	}
	senderMembership := event.Membership(findEventAndReadString(authEvents, event.StateMember.Type, evt.Sender.String(), "membership", "leave"))
	if senderMembership != event.MembershipJoin {
		// 6. If the sender’s current membership state is not join, reject.
		return ErrNotInRoom
	}
	powerLevels, err := getPowerLevels(roomVersion, authEvents, createEvt)
	if err != nil {
		return err
	}
	senderPL := powerLevels.GetUserLevel(evt.Sender)
	if evt.Type == event.StateThirdPartyInvite.Type {
		// 7.1. Allow if and only if sender’s current power level is greater than or equal to the invite level.
		if senderPL >= powerLevels.Invite() {
			return nil
		}
		return ErrInsufficientPowerForThirdPartyInvite
	}
	typeClass := event.MessageEventType
	if evt.StateKey != nil {
		typeClass = event.StateEventType
	}
	evtLevel := powerLevels.GetEventLevel(event.Type{Type: evt.Type, Class: typeClass})
	if evtLevel > senderPL {
		// 8. If the event type’s required power level is greater than the sender’s power level, reject.
		return fmt.Errorf("%w (%d > %d)", ErrInsufficientPowerLevel, evtLevel, senderPL)
	}

	if evt.StateKey != nil && strings.HasPrefix(*evt.StateKey, "@") && *evt.StateKey != evt.Sender.String() {
		// 9. If the event has a state_key that starts with an @ and does not match the sender, reject.
		return ErrMismatchingPrivateStateKey
	}

	if evt.Type == event.StatePowerLevels.Type {
		// 10. If type is m.room.power_levels:
		return authorizePowerLevels(roomVersion, evt, createEvt, authEvents)
	}

	// 11. Otherwise, allow.
	return nil
}

var ErrUserIDNotAString = errors.New("not a string")
var ErrUserIDNotValid = errors.New("not a valid user ID")

func isValidUserID(roomVersion id.RoomVersion, userID gjson.Result) error {
	if userID.Type != gjson.String {
		return ErrUserIDNotAString
	}
	// In a future room version, user IDs will have stricter validation
	_, _, err := id.UserID(userID.Str).Parse()
	if err != nil {
		return ErrUserIDNotValid
	}
	return nil
}

func authorizeCreate(roomVersion id.RoomVersion, evt *pdu.PDU) error {
	if len(evt.PrevEvents) > 0 {
		// 1.1. If it has any prev_events, reject.
		return ErrCreateHasPrevEvents
	}
	if roomVersion.RoomIDIsCreateEventID() {
		if evt.RoomID != "" {
			// 1.2. If the event has a room_id, reject.
			return ErrCreateHasRoomID
		}
	} else {
		_, _, server := id.ParseCommonIdentifier(evt.RoomID)
		if server == "" || server != evt.Sender.Homeserver() {
			// 1.2. (v11 and below) If the domain of the room_id does not match the domain of the sender, reject.
			return ErrRoomIDDoesntMatchSender
		}
	}
	if !roomVersion.IsKnown() {
		// 1.3. If content.room_version is present and is not a recognised version, reject.
		return fmt.Errorf("%w %s", ErrUnknownRoomVersion, roomVersion)
	}
	if roomVersion.PrivilegedRoomCreators() {
		additionalCreators := gjson.GetBytes(evt.Content, "additional_creators")
		if additionalCreators.Exists() {
			if !additionalCreators.IsArray() {
				return fmt.Errorf("%w: not an array", ErrInvalidAdditionalCreators)
			}
			for i, item := range additionalCreators.Array() {
				// 1.4. If additional_creators is present in content and is not an array of strings
				//      where each string passes the same user ID validation applied to sender, reject.
				if err := isValidUserID(roomVersion, item); err != nil {
					return fmt.Errorf("%w: item #%d %w", ErrInvalidAdditionalCreators, i+1, err)
				}
			}
		}
	}
	if roomVersion.CreatorInContent() {
		// 1.4. (v10 and below) If content has no creator property, reject.
		if !gjson.GetBytes(evt.Content, "creator").Exists() {
			return ErrMissingCreator
		}
	}
	// 1.5. Otherwise, allow.
	return nil
}

func authorizeMember(roomVersion id.RoomVersion, evt, createEvt *pdu.PDU, authEvents []*pdu.PDU, getKey pdu.GetKeyFunc) error {
	membership := event.Membership(gjson.GetBytes(evt.Content, "membership").Str)
	if evt.StateKey == nil {
		// 5.1. If there is no state_key property, or no membership property in content, reject.
		return ErrMemberNotState
	}
	authorizedVia := id.UserID(gjson.GetBytes(evt.Content, "authorised_via_users_server").Str)
	if authorizedVia != "" {
		homeserver := authorizedVia.Homeserver()
		err := evt.VerifySignature(roomVersion, homeserver, getKey)
		if err != nil {
			// 5.2. If content has a join_authorised_via_users_server key:
			// 5.2.1. If the event is not validly signed by the homeserver of the user ID denoted by the key, reject.
			return fmt.Errorf("%w: %w", ErrNotSignedByAuthoriser, err)
		}
	}
	targetPrevMembership := event.Membership(findEventAndReadString(authEvents, event.StateMember.Type, *evt.StateKey, "membership", "leave"))
	senderMembership := event.Membership(findEventAndReadString(authEvents, event.StateMember.Type, evt.Sender.String(), "membership", "leave"))
	switch membership {
	case event.MembershipJoin:
		createEvtID, err := createEvt.GetEventID(roomVersion)
		if err != nil {
			return fmt.Errorf("failed to get create event ID: %w", err)
		}
		creator := createEvt.Sender.String()
		if roomVersion.CreatorInContent() {
			creator = gjson.GetBytes(evt.Content, "creator").Str
		}
		if len(evt.PrevEvents) == 1 &&
			len(evt.AuthEvents) <= 1 &&
			evt.PrevEvents[0] == createEvtID &&
			*evt.StateKey == creator {
			// 5.3.1. If the only previous event is an m.room.create and the state_key is the sender of the m.room.create, allow.
			return nil
		}
		// Spec wart: this would make more sense before the check above.
		// Now you can set anyone as the sender of the first join.
		if evt.Sender.String() != *evt.StateKey {
			// 5.3.2. If the sender does not match state_key, reject.
			return ErrCantJoinOtherUser
		}

		if senderMembership == event.MembershipBan {
			// 5.3.3. If the sender is banned, reject.
			return ErrCantJoinBanned
		}

		joinRule := event.JoinRule(findEventAndReadString(authEvents, event.StateJoinRules.Type, "", "join_rule", "invite"))
		switch joinRule {
		case event.JoinRuleKnock:
			if !roomVersion.Knocks() {
				return ErrInvalidJoinRule
			}
			fallthrough
		case event.JoinRuleInvite:
			// 5.3.4. If the join_rule is invite or knock then allow if membership state is invite or join.
			if targetPrevMembership == event.MembershipJoin || targetPrevMembership == event.MembershipInvite {
				return nil
			}
			return ErrCantJoinWithoutInvite
		case event.JoinRuleKnockRestricted:
			if !roomVersion.KnockRestricted() {
				return ErrInvalidJoinRule
			}
			fallthrough
		case event.JoinRuleRestricted:
			if joinRule == event.JoinRuleRestricted && !roomVersion.RestrictedJoins() {
				return ErrInvalidJoinRule
			}
			if targetPrevMembership == event.MembershipJoin || targetPrevMembership == event.MembershipInvite {
				// 5.3.5.1. If membership state is join or invite, allow.
				return nil
			}
			powerLevels, err := getPowerLevels(roomVersion, authEvents, createEvt)
			if err != nil {
				return err
			}
			if powerLevels.GetUserLevel(authorizedVia) < powerLevels.Invite() {
				// 5.3.5.2. If the join_authorised_via_users_server key in content is not a user with sufficient permission to invite other users, reject.
				return ErrAuthoriserCantInvite
			}
			authorizerMembership := event.Membership(findEventAndReadString(authEvents, event.StateMember.Type, authorizedVia.String(), "membership", string(event.MembershipLeave)))
			if authorizerMembership != event.MembershipJoin {
				return ErrAuthoriserNotInRoom
			}
			// 5.3.5.3. Otherwise, allow.
			return nil
		case event.JoinRulePublic:
			// 5.3.6. If the join_rule is public, allow.
			return nil
		default:
			// 5.3.7. Otherwise, reject.
			return ErrInvalidJoinRule
		}
	case event.MembershipInvite:
		tpiVal := gjson.GetBytes(evt.Content, "third_party_invite")
		if tpiVal.Exists() {
			if targetPrevMembership == event.MembershipBan {
				return ErrThirdPartyInviteBanned
			}
			signed := tpiVal.Get("signed")
			mxid := signed.Get("mxid").Str
			token := signed.Get("token").Str
			if mxid == "" || token == "" {
				// 5.4.1.2. If content.third_party_invite does not have a signed property, reject.
				// 5.4.1.3. If signed does not have mxid and token properties, reject.
				return ErrThirdPartyInviteMissingFields
			}
			if mxid != *evt.StateKey {
				// 5.4.1.4. If mxid does not match state_key, reject.
				return ErrThirdPartyInviteMXIDMismatch
			}
			tpiEvt := findEvent(authEvents, event.StateThirdPartyInvite.Type, token)
			if tpiEvt == nil {
				// 5.4.1.5. If there is no m.room.third_party_invite event in the current room state with state_key matching token, reject.
				return ErrThirdPartyInviteNotFound
			}
			if tpiEvt.Sender != evt.Sender {
				// 5.4.1.6. If sender does not match sender of the m.room.third_party_invite, reject.
				return ErrThirdPartyInviteSenderMismatch
			}
			var keys []id.Ed25519
			const ed25519Base64Len = 43
			oldPubKey := gjson.GetBytes(evt.Content, "public_key.token")
			if oldPubKey.Type == gjson.String && len(oldPubKey.Str) == ed25519Base64Len {
				keys = append(keys, id.Ed25519(oldPubKey.Str))
			}
			gjson.GetBytes(evt.Content, "public_keys").ForEach(func(key, value gjson.Result) bool {
				if key.Type != gjson.Number {
					return false
				}
				if value.Type == gjson.String && len(value.Str) == ed25519Base64Len {
					keys = append(keys, id.Ed25519(value.Str))
				}
				return true
			})
			rawSigned := jsontext.Value(exstrings.UnsafeBytes(signed.Str))
			var validated bool
			for _, key := range keys {
				if signutil.VerifyJSONAny(key, rawSigned) == nil {
					validated = true
				}
			}
			if validated {
				// 4.4.1.7. If any signature in signed matches any public key in the m.room.third_party_invite event, allow.
				return nil
			}
			// 4.4.1.8. Otherwise, reject.
			return ErrThirdPartyInviteNotSigned
		}
		if senderMembership != event.MembershipJoin {
			// 5.4.2. If the sender’s current membership state is not join, reject.
			return ErrInviterNotInRoom
		}
		// 5.4.3. If target user’s current membership state is join or ban, reject.
		if targetPrevMembership == event.MembershipJoin {
			return ErrInviteTargetAlreadyInRoom
		} else if targetPrevMembership == event.MembershipBan {
			return ErrInviteTargetBanned
		}
		powerLevels, err := getPowerLevels(roomVersion, authEvents, createEvt)
		if err != nil {
			return err
		}
		if powerLevels.GetUserLevel(evt.Sender) >= powerLevels.Invite() {
			// 5.4.4. If the sender’s power level is greater than or equal to the invite level, allow.
			return nil
		}
		// 5.4.5. Otherwise, reject.
		return ErrInsufficientPermissionForInvite
	case event.MembershipLeave:
		if evt.Sender.String() == *evt.StateKey {
			// 5.5.1. If the sender matches state_key, allow if and only if that user’s current membership state is invite, join, or knock.
			if senderMembership == event.MembershipInvite ||
				senderMembership == event.MembershipJoin ||
				(senderMembership == event.MembershipKnock && roomVersion.Knocks()) {
				return nil
			}
			return ErrCantLeaveWithoutBeingInRoom
		}
		if senderMembership != event.MembershipLeave {
			// 5.5.2. If the sender’s current membership state is not join, reject.
			return ErrCantKickWithoutBeingInRoom
		}
		powerLevels, err := getPowerLevels(roomVersion, authEvents, createEvt)
		if err != nil {
			return err
		}
		senderLevel := powerLevels.GetUserLevel(evt.Sender)
		if targetPrevMembership == event.MembershipBan && senderLevel < powerLevels.Ban() {
			// 5.5.3. If the target user’s current membership state is ban, and the sender’s power level is less than the ban level, reject.
			return ErrInsufficientPermissionForUnban
		}
		if senderLevel >= powerLevels.Kick() && powerLevels.GetUserLevel(id.UserID(*evt.StateKey)) < senderLevel {
			// 5.5.4. If the sender’s power level is greater than or equal to the kick level, and the target user’s power level is less than the sender’s power level, allow.
			return nil
		}
		// TODO separate errors for < kick and < target user level?
		// 5.5.5. Otherwise, reject.
		return ErrInsufficientPermissionForKick
	case event.MembershipBan:
		if senderMembership != event.MembershipLeave {
			// 5.6.1. If the sender’s current membership state is not join, reject.
			return ErrCantBanWithoutBeingInRoom
		}
		powerLevels, err := getPowerLevels(roomVersion, authEvents, createEvt)
		if err != nil {
			return err
		}
		senderLevel := powerLevels.GetUserLevel(evt.Sender)
		if senderLevel >= powerLevels.Ban() && powerLevels.GetUserLevel(id.UserID(*evt.StateKey)) < senderLevel {
			// 5.6.2. If the sender’s power level is greater than or equal to the ban level, and the target user’s power level is less than the sender’s power level, allow.
			return nil
		}
		// 5.6.3. Otherwise, reject.
		return ErrInsufficientPermissionForBan
	case event.MembershipKnock:
		joinRule := event.JoinRule(findEventAndReadString(authEvents, event.StateJoinRules.Type, "", "join_rule", "invite"))
		validKnockRule := roomVersion.Knocks() && joinRule == event.JoinRuleKnock
		validKnockRestrictedRule := roomVersion.KnockRestricted() && joinRule == event.JoinRuleKnockRestricted
		if !validKnockRule && !validKnockRestrictedRule {
			// 5.7.1. If the join_rule is anything other than knock or knock_restricted, reject.
			return ErrNotKnockableRoom
		}
		if evt.Sender.String() != *evt.StateKey {
			// 5.7.2. If the sender does not match state_key, reject.
			return ErrCantKnockOtherUser
		}
		if senderMembership != event.MembershipBan && senderMembership != event.MembershipInvite && senderMembership != event.MembershipJoin {
			// 5.7.3. If the sender’s current membership is not ban, invite, or join, allow.
			return nil
		}
		// 5.7.4. Otherwise, reject.
		return ErrCantKnockWhileInRoom
	default:
		// 5.8. Otherwise, the membership is unknown. Reject.
		return ErrUnknownMembership
	}
}

func authorizePowerLevels(roomVersion id.RoomVersion, evt, createEvt *pdu.PDU, authEvents []*pdu.PDU) error {
	if roomVersion.ValidatePowerLevelInts() {
		for _, key := range []string{"users_default", "events_default", "state_default", "ban", "redact", "kick", "invite"} {
			res := gjson.GetBytes(evt.Content, key)
			if !res.Exists() {
				continue
			}
			if parseIntWithVersion(roomVersion, res) == nil {
				// 10.1. If any of the properties users_default, events_default, state_default, ban, redact, kick, or invite in content are present and not an integer, reject.
				return fmt.Errorf("%w %s", ErrTopLevelPLNotInteger, key)
			}
		}
		for _, key := range []string{"events", "notifications"} {
			obj := gjson.GetBytes(evt.Content, key)
			if !obj.Exists() {
				continue
			}
			// 10.2. If either of the properties events or notifications in content are present and not an object [...], reject.
			if !obj.IsObject() {
				return fmt.Errorf("%w %s", ErrTopLevelPLNotInteger, key)
			}
			var err error
			// 10.2. [...] are not an object with values that are integers, reject.
			obj.ForEach(func(innerKey, value gjson.Result) bool {
				if parseIntWithVersion(roomVersion, value) == nil {
					err = fmt.Errorf("%w %s.%s", ErrPLNotInteger, key, innerKey.Str)
					return false
				}
				return true
			})
			if err != nil {
				return err
			}
		}
	}
	var creators []id.UserID
	if roomVersion.PrivilegedRoomCreators() {
		creators = append(creators, createEvt.Sender)
		gjson.GetBytes(createEvt.Content, "additional_creators").ForEach(func(key, value gjson.Result) bool {
			creators = append(creators, id.UserID(value.Str))
			return true
		})
	}
	users := gjson.GetBytes(evt.Content, "users")
	if users.Exists() {
		if !users.IsObject() {
			// 10.3. If the users property in content is not an object [...], reject.
			return fmt.Errorf("%w users", ErrTopLevelPLNotInteger)
		}
		var err error
		users.ForEach(func(key, value gjson.Result) bool {
			if validatorErr := isValidUserID(roomVersion, key); validatorErr != nil {
				// 10.3. [...] is not an object with keys that are valid user IDs [...], reject.
				err = fmt.Errorf("%w: %q %w", ErrInvalidUserIDInPL, key.Str, validatorErr)
				return false
			}
			if parseIntWithVersion(roomVersion, value) == nil {
				// 10.3. [...] is not an object [...] with values that are integers, reject.
				err = fmt.Errorf("%w %q", ErrUserPLNotInteger, key.Str)
				return false
			}
			// creators is only filled if the room version has privileged room creators
			if slices.Contains(creators, id.UserID(key.Str)) {
				// 10.4. If the users property in content contains the sender of the m.room.create event or any of
				//       the additional_creators array (if present) from the content of the m.room.create event, reject.
				err = fmt.Errorf("%w: %q", ErrCreatorInPowerLevels, key.Str)
				return false
			}
			return true
		})
		if err != nil {
			return err
		}
	}
	oldPL := findEvent(authEvents, event.StatePowerLevels.Type, "")
	if oldPL == nil {
		// 10.5. If there is no previous m.room.power_levels event in the room, allow.
		return nil
	}
	if slices.Contains(creators, evt.Sender) {
		// Skip remaining checks for creators
		return nil
	}
	senderPLPtr := parsePythonInt(gjson.GetBytes(oldPL.Content, exgjson.Path("users", evt.Sender.String())))
	if senderPLPtr == nil {
		senderPLPtr = parsePythonInt(gjson.GetBytes(oldPL.Content, "users_default"))
		if senderPLPtr == nil {
			senderPLPtr = ptr.Ptr(0)
		}
	}
	for _, key := range []string{"users_default", "events_default", "state_default", "ban", "redact", "kick", "invite"} {
		oldVal := gjson.GetBytes(oldPL.Content, key)
		newVal := gjson.GetBytes(evt.Content, key)
		if err := allowPowerChange(roomVersion, *senderPLPtr, key, oldVal, newVal); err != nil {
			return err
		}
	}
	if err := allowPowerChangeMap(
		roomVersion, *senderPLPtr, "events", "",
		gjson.GetBytes(oldPL.Content, "events"),
		gjson.GetBytes(evt.Content, "events"),
	); err != nil {
		return err
	}
	if err := allowPowerChangeMap(
		roomVersion, *senderPLPtr, "notifications", "",
		gjson.GetBytes(oldPL.Content, "notifications"),
		gjson.GetBytes(evt.Content, "notifications"),
	); err != nil {
		return err
	}
	if err := allowPowerChangeMap(
		roomVersion, *senderPLPtr, "users", evt.Sender.String(),
		gjson.GetBytes(oldPL.Content, "users"),
		gjson.GetBytes(evt.Content, "users"),
	); err != nil {
		return err
	}
	return nil
}

func allowPowerChangeMap(roomVersion id.RoomVersion, maxVal int, path, ownID string, old, new gjson.Result) (err error) {
	old.ForEach(func(key, value gjson.Result) bool {
		newVal := new.Get(exgjson.Path(key.Str))
		err = allowPowerChange(roomVersion, maxVal, path+"."+key.Str, value, newVal)
		if err == nil && ownID != "" && key.Str != ownID {
			parsedOldVal := parseIntWithVersion(roomVersion, value)
			parsedNewVal := parseIntWithVersion(roomVersion, newVal)
			if *parsedOldVal >= maxVal && *parsedOldVal != *parsedNewVal {
				err = fmt.Errorf("%w: can't change users.%s from %s to %s with sender level %d", ErrInvalidUserPowerChange, key.Str, stringifyForError(value), stringifyForError(newVal), maxVal)
			}
		}
		return err == nil
	})
	if err != nil {
		return
	}
	new.ForEach(func(key, value gjson.Result) bool {
		err = allowPowerChange(roomVersion, maxVal, path+"."+key.Str, old.Get(exgjson.Path(key.Str)), value)
		return err == nil
	})
	return
}

func allowPowerChange(roomVersion id.RoomVersion, maxVal int, path string, old, new gjson.Result) error {
	oldVal := parseIntWithVersion(roomVersion, old)
	newVal := parseIntWithVersion(roomVersion, new)
	if oldVal == nil {
		if newVal == nil || *newVal <= maxVal {
			return nil
		}
	} else if newVal == nil {
		if *oldVal <= maxVal {
			return nil
		}
	} else if *oldVal == *newVal || (*oldVal <= maxVal && *newVal <= maxVal) {
		return nil
	}
	return fmt.Errorf("%w can't change %s from %s to %s with sender level %d", ErrInvalidPowerChange, path, stringifyForError(old), stringifyForError(new), maxVal)
}

func stringifyForError(val gjson.Result) string {
	if !val.Exists() {
		return "null"
	}
	return val.Raw
}

func findEvent(events []*pdu.PDU, evtType, stateKey string) *pdu.PDU {
	for _, evt := range events {
		if evt.Type == evtType && *evt.StateKey == stateKey {
			return evt
		}
	}
	return nil
}

func findEventAndReadData[T any](events []*pdu.PDU, evtType, stateKey string, reader func(evt *pdu.PDU) T) T {
	return reader(findEvent(events, evtType, stateKey))
}

func findEventAndReadString(events []*pdu.PDU, evtType, stateKey, fieldPath, defVal string) string {
	return findEventAndReadData(events, evtType, stateKey, func(evt *pdu.PDU) string {
		if evt == nil {
			return defVal
		}
		res := gjson.GetBytes(evt.Content, fieldPath)
		if res.Type != gjson.String {
			return defVal
		}
		return res.Str
	})
}

func getPowerLevels(roomVersion id.RoomVersion, authEvents []*pdu.PDU, createEvt *pdu.PDU) (*event.PowerLevelsEventContent, error) {
	var err error
	powerLevels := findEventAndReadData(authEvents, event.StatePowerLevels.Type, "", func(evt *pdu.PDU) *event.PowerLevelsEventContent {
		if evt == nil {
			return nil
		}
		content := evt.Content
		out := &event.PowerLevelsEventContent{}
		if !roomVersion.ValidatePowerLevelInts() {
			safeParsePowerLevels(content, out)
		} else {
			err = json.Unmarshal(content, out)
		}
		return out
	})
	if err != nil {
		// This should never happen thanks to safeParsePowerLevels for v1-9 and strict validation in v10+
		return nil, fmt.Errorf("%w: %w", ErrFailedToParsePowerLevels, err)
	}
	if roomVersion.PrivilegedRoomCreators() {
		if powerLevels == nil {
			powerLevels = &event.PowerLevelsEventContent{}
		}
		powerLevels.CreateEvent, err = createEvt.ToClientEvent(roomVersion)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToParsePowerLevels, err)
		}
		err = powerLevels.CreateEvent.Content.ParseRaw(powerLevels.CreateEvent.Type)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToParsePowerLevels, err)
		}
	} else if powerLevels == nil {
		powerLevels = &event.PowerLevelsEventContent{
			Users: map[id.UserID]int{
				createEvt.Sender: 100,
			},
		}
	}
	return powerLevels, nil
}

func parseIntWithVersion(roomVersion id.RoomVersion, val gjson.Result) *int {
	if roomVersion.ValidatePowerLevelInts() {
		if val.Type != gjson.Number {
			return nil
		}
		return ptr.Ptr(int(val.Int()))
	}
	return parsePythonInt(val)
}

func parsePythonInt(val gjson.Result) *int {
	switch val.Type {
	case gjson.True:
		return ptr.Ptr(1)
	case gjson.False:
		return ptr.Ptr(0)
	case gjson.Number:
		return ptr.Ptr(int(val.Int()))
	case gjson.String:
		// strconv.Atoi accepts signs as well as leading zeroes, so we just need to trim spaces beforehand
		num, err := strconv.Atoi(strings.TrimSpace(val.Str))
		if err != nil {
			return nil
		}
		return &num
	default:
		// Python int() doesn't accept nulls, arrays or dicts
		return nil
	}
}

func safeParsePowerLevels(content jsontext.Value, into *event.PowerLevelsEventContent) {
	*into = event.PowerLevelsEventContent{
		Users:           make(map[id.UserID]int),
		UsersDefault:    ptr.Val(parsePythonInt(gjson.GetBytes(content, "users_default"))),
		Events:          make(map[string]int),
		EventsDefault:   ptr.Val(parsePythonInt(gjson.GetBytes(content, "events_default"))),
		Notifications:   nil, // irrelevant for event auth
		StateDefaultPtr: parsePythonInt(gjson.GetBytes(content, "state_default")),
		InvitePtr:       parsePythonInt(gjson.GetBytes(content, "invite")),
		KickPtr:         parsePythonInt(gjson.GetBytes(content, "kick")),
		BanPtr:          parsePythonInt(gjson.GetBytes(content, "ban")),
		RedactPtr:       parsePythonInt(gjson.GetBytes(content, "redact")),
	}
	gjson.GetBytes(content, "events").ForEach(func(key, value gjson.Result) bool {
		if key.Type != gjson.String {
			return false
		}
		val := parsePythonInt(value)
		if val != nil {
			into.Events[key.Str] = *val
		}
		return true
	})
	gjson.GetBytes(content, "users").ForEach(func(key, value gjson.Result) bool {
		if key.Type != gjson.String {
			return false
		}
		val := parsePythonInt(value)
		if val == nil {
			return false
		}
		userID := id.UserID(key.Str)
		if _, _, err := userID.Parse(); err != nil {
			return false
		}
		into.Users[userID] = *val
		return true
	})
}
