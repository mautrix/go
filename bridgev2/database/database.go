// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"encoding/json"
	"reflect"
	"strings"

	"go.mau.fi/util/dbutil"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"

	"maunium.net/go/mautrix/bridgev2/networkid"

	"maunium.net/go/mautrix/bridgev2/database/upgrades"
)

type Database struct {
	*dbutil.Database

	BridgeID            networkid.BridgeID
	Portal              *PortalQuery
	Ghost               *GhostQuery
	Message             *MessageQuery
	DisappearingMessage *DisappearingMessageQuery
	Reaction            *ReactionQuery
	User                *UserQuery
	UserLogin           *UserLoginQuery
	UserPortal          *UserPortalQuery
}

func New(bridgeID networkid.BridgeID, db *dbutil.Database) *Database {
	db.UpgradeTable = upgrades.Table
	return &Database{
		Database:            db,
		BridgeID:            bridgeID,
		Portal:              &PortalQuery{bridgeID, dbutil.MakeQueryHelper(db, newPortal)},
		Ghost:               &GhostQuery{bridgeID, dbutil.MakeQueryHelper(db, newGhost)},
		Message:             &MessageQuery{bridgeID, dbutil.MakeQueryHelper(db, newMessage)},
		DisappearingMessage: &DisappearingMessageQuery{bridgeID, dbutil.MakeQueryHelper(db, newDisappearingMessage)},
		Reaction:            &ReactionQuery{bridgeID, dbutil.MakeQueryHelper(db, newReaction)},
		User:                &UserQuery{bridgeID, dbutil.MakeQueryHelper(db, newUser)},
		UserLogin:           &UserLoginQuery{bridgeID, dbutil.MakeQueryHelper(db, newUserLogin)},
		UserPortal:          &UserPortalQuery{bridgeID, dbutil.MakeQueryHelper(db, newUserPortal)},
	}
}

func ensureBridgeIDMatches(ptr *networkid.BridgeID, expected networkid.BridgeID) {
	if *ptr == "" {
		*ptr = expected
	} else if *ptr != expected {
		panic("bridge ID mismatch")
	}
}

func GetNumberFromMap[T constraints.Integer | constraints.Float](m map[string]any, key string) (T, bool) {
	if val, found := m[key]; found {
		floatVal, ok := val.(float64)
		if ok {
			return T(floatVal), true
		}
		tVal, ok := val.(T)
		if ok {
			return tVal, true
		}
	}
	return 0, false
}

func unmarshalMerge(input []byte, data any, extra *map[string]any) error {
	err := json.Unmarshal(input, data)
	if err != nil {
		return err
	}
	err = json.Unmarshal(input, extra)
	if err != nil {
		return err
	}
	if *extra == nil {
		*extra = make(map[string]any)
	}
	return nil
}

func marshalMerge(data any, extra map[string]any) ([]byte, error) {
	if extra == nil {
		return json.Marshal(data)
	}
	merged := make(map[string]any)
	maps.Copy(merged, extra)
	dataRef := reflect.ValueOf(data).Elem()
	dataType := dataRef.Type()
	for _, field := range reflect.VisibleFields(dataType) {
		parts := strings.Split(field.Tag.Get("json"), ",")
		if len(parts) == 0 || len(parts[0]) == 0 || parts[0] == "-" {
			continue
		}
		fieldVal := dataRef.FieldByIndex(field.Index)
		if fieldVal.IsZero() {
			delete(merged, parts[0])
		} else {
			merged[parts[0]] = fieldVal.Interface()
		}
	}
	return json.Marshal(merged)
}
