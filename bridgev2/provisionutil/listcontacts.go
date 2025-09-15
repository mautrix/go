// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package provisionutil

import (
	"context"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
)

type RespGetContactList struct {
	Contacts []*RespResolveIdentifier `json:"contacts"`
}

type RespSearchUsers struct {
	Results []*RespResolveIdentifier `json:"results"`
}

func GetContactList(ctx context.Context, login *bridgev2.UserLogin) (*RespGetContactList, error) {
	api, ok := login.Client.(bridgev2.ContactListingNetworkAPI)
	if !ok {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support listing contacts"))
	}
	resp, err := api.GetContactList(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to get contact list")
		return nil, err
	}
	return &RespGetContactList{
		Contacts: processResolveIdentifiers(ctx, login.Bridge, resp, false),
	}, nil
}

func SearchUsers(ctx context.Context, login *bridgev2.UserLogin, query string) (*RespSearchUsers, error) {
	api, ok := login.Client.(bridgev2.UserSearchingNetworkAPI)
	if !ok {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support searching for users"))
	}
	resp, err := api.SearchUsers(ctx, query)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to get contact list")
		return nil, err
	}
	return &RespSearchUsers{
		Results: processResolveIdentifiers(ctx, login.Bridge, resp, true),
	}, nil
}

func processResolveIdentifiers(ctx context.Context, br *bridgev2.Bridge, resp []*bridgev2.ResolveIdentifierResponse, syncInfo bool) (apiResp []*RespResolveIdentifier) {
	apiResp = make([]*RespResolveIdentifier, len(resp))
	for i, contact := range resp {
		apiContact := &RespResolveIdentifier{
			ID: contact.UserID,
		}
		apiResp[i] = apiContact
		if contact.UserInfo != nil {
			if contact.UserInfo.Name != nil {
				apiContact.Name = *contact.UserInfo.Name
			}
			if contact.UserInfo.Identifiers != nil {
				apiContact.Identifiers = contact.UserInfo.Identifiers
			}
		}
		if contact.Ghost != nil {
			if syncInfo && contact.UserInfo != nil {
				contact.Ghost.UpdateInfo(ctx, contact.UserInfo)
			}
			if contact.Ghost.Name != "" {
				apiContact.Name = contact.Ghost.Name
			}
			if len(contact.Ghost.Identifiers) >= len(apiContact.Identifiers) {
				apiContact.Identifiers = contact.Ghost.Identifiers
			}
			apiContact.AvatarURL = contact.Ghost.AvatarMXC
			apiContact.MXID = contact.Ghost.Intent.GetMXID()
		}
		if contact.Chat != nil {
			if contact.Chat.Portal == nil {
				var err error
				contact.Chat.Portal, err = br.GetPortalByKey(ctx, contact.Chat.PortalKey)
				if err != nil {
					zerolog.Ctx(ctx).Err(err).Msg("Failed to get portal")
				}
			}
			if contact.Chat.Portal != nil {
				apiContact.DMRoomID = contact.Chat.Portal.MXID
			}
		}
	}
	return
}
