// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/hicli/database/upgrades"
)

type Database struct {
	*dbutil.Database

	Account        AccountQuery
	AccountData    AccountDataQuery
	Room           RoomQuery
	Event          EventQuery
	CurrentState   CurrentStateQuery
	Timeline       TimelineQuery
	SessionRequest SessionRequestQuery
}

func New(rawDB *dbutil.Database) *Database {
	rawDB.UpgradeTable = upgrades.Table
	return &Database{
		Database: rawDB,

		Account:        AccountQuery{QueryHelper: dbutil.MakeQueryHelper(rawDB, newAccount)},
		AccountData:    AccountDataQuery{QueryHelper: dbutil.MakeQueryHelper(rawDB, newAccountData)},
		Room:           RoomQuery{QueryHelper: dbutil.MakeQueryHelper(rawDB, newRoom)},
		Event:          EventQuery{QueryHelper: dbutil.MakeQueryHelper(rawDB, newEvent)},
		CurrentState:   CurrentStateQuery{Database: rawDB},
		Timeline:       TimelineQuery{Database: rawDB},
		SessionRequest: SessionRequestQuery{QueryHelper: dbutil.MakeQueryHelper(rawDB, newSessionRequest)},
	}
}

func newSessionRequest(_ *dbutil.QueryHelper[*SessionRequest]) *SessionRequest {
	return &SessionRequest{}
}

func newEvent(_ *dbutil.QueryHelper[*Event]) *Event {
	return &Event{}
}

func newRoom(_ *dbutil.QueryHelper[*Room]) *Room {
	return &Room{}
}

func newAccountData(_ *dbutil.QueryHelper[*AccountData]) *AccountData {
	return &AccountData{}
}

func newAccount(_ *dbutil.QueryHelper[*Account]) *Account {
	return &Account{}
}
