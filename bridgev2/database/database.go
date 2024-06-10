// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"

	"maunium.net/go/mautrix/bridgev2/database/upgrades"
)

type Database struct {
	*dbutil.Database

	BridgeID  networkid.BridgeID
	Portal    *PortalQuery
	Ghost     *GhostQuery
	Message   *MessageQuery
	Reaction  *ReactionQuery
	User      *UserQuery
	UserLogin *UserLoginQuery
}

func New(bridgeID networkid.BridgeID, db *dbutil.Database) *Database {
	db.UpgradeTable = upgrades.Table
	return &Database{
		Database:  db,
		BridgeID:  bridgeID,
		Portal:    &PortalQuery{bridgeID, dbutil.MakeQueryHelper(db, newPortal)},
		Ghost:     &GhostQuery{bridgeID, dbutil.MakeQueryHelper(db, newGhost)},
		Message:   &MessageQuery{bridgeID, dbutil.MakeQueryHelper(db, newMessage)},
		Reaction:  &ReactionQuery{bridgeID, dbutil.MakeQueryHelper(db, newReaction)},
		User:      &UserQuery{bridgeID, dbutil.MakeQueryHelper(db, newUser)},
		UserLogin: &UserLoginQuery{bridgeID, dbutil.MakeQueryHelper(db, newUserLogin)},
	}
}

func ensureBridgeIDMatches(ptr *networkid.BridgeID, expected networkid.BridgeID) {
	if *ptr == "" {
		*ptr = expected
	} else if *ptr != expected {
		panic("bridge ID mismatch")
	}
}
