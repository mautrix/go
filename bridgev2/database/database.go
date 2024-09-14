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
	BackfillTask        *BackfillTaskQuery
	KV                  *KVQuery
}

type MetaMerger interface {
	CopyFrom(other any)
}

type MetaTypeCreator func() any

type MetaTypes struct {
	Portal    MetaTypeCreator
	Ghost     MetaTypeCreator
	Message   MetaTypeCreator
	Reaction  MetaTypeCreator
	UserLogin MetaTypeCreator
}

type blankMeta struct{}

var blankMetaItem = &blankMeta{}

func blankMetaCreator() any {
	return blankMetaItem
}

func New(bridgeID networkid.BridgeID, mt MetaTypes, db *dbutil.Database) *Database {
	if mt.Portal == nil {
		mt.Portal = blankMetaCreator
	}
	if mt.Ghost == nil {
		mt.Ghost = blankMetaCreator
	}
	if mt.Message == nil {
		mt.Message = blankMetaCreator
	}
	if mt.Reaction == nil {
		mt.Reaction = blankMetaCreator
	}
	if mt.UserLogin == nil {
		mt.UserLogin = blankMetaCreator
	}
	db.UpgradeTable = upgrades.Table
	return &Database{
		Database: db,
		BridgeID: bridgeID,
		Portal: &PortalQuery{
			BridgeID: bridgeID,
			MetaType: mt.Portal,
			QueryHelper: dbutil.MakeQueryHelper(db, func(_ *dbutil.QueryHelper[*Portal]) *Portal {
				return (&Portal{}).ensureHasMetadata(mt.Portal)
			}),
		},
		Ghost: &GhostQuery{
			BridgeID: bridgeID,
			MetaType: mt.Ghost,
			QueryHelper: dbutil.MakeQueryHelper(db, func(_ *dbutil.QueryHelper[*Ghost]) *Ghost {
				return (&Ghost{}).ensureHasMetadata(mt.Ghost)
			}),
		},
		Message: &MessageQuery{
			BridgeID: bridgeID,
			MetaType: mt.Message,
			QueryHelper: dbutil.MakeQueryHelper(db, func(_ *dbutil.QueryHelper[*Message]) *Message {
				return (&Message{}).ensureHasMetadata(mt.Message)
			}),
		},
		DisappearingMessage: &DisappearingMessageQuery{
			BridgeID: bridgeID,
			QueryHelper: dbutil.MakeQueryHelper(db, func(_ *dbutil.QueryHelper[*DisappearingMessage]) *DisappearingMessage {
				return &DisappearingMessage{}
			}),
		},
		Reaction: &ReactionQuery{
			BridgeID: bridgeID,
			MetaType: mt.Reaction,
			QueryHelper: dbutil.MakeQueryHelper(db, func(_ *dbutil.QueryHelper[*Reaction]) *Reaction {
				return (&Reaction{}).ensureHasMetadata(mt.Reaction)
			}),
		},
		User: &UserQuery{
			BridgeID: bridgeID,
			QueryHelper: dbutil.MakeQueryHelper(db, func(_ *dbutil.QueryHelper[*User]) *User {
				return &User{}
			}),
		},
		UserLogin: &UserLoginQuery{
			BridgeID: bridgeID,
			MetaType: mt.UserLogin,
			QueryHelper: dbutil.MakeQueryHelper(db, func(_ *dbutil.QueryHelper[*UserLogin]) *UserLogin {
				return (&UserLogin{}).ensureHasMetadata(mt.UserLogin)
			}),
		},
		UserPortal: &UserPortalQuery{
			BridgeID: bridgeID,
			QueryHelper: dbutil.MakeQueryHelper(db, func(_ *dbutil.QueryHelper[*UserPortal]) *UserPortal {
				return &UserPortal{}
			}),
		},
		BackfillTask: &BackfillTaskQuery{
			BridgeID: bridgeID,
			QueryHelper: dbutil.MakeQueryHelper(db, func(_ *dbutil.QueryHelper[*BackfillTask]) *BackfillTask {
				return &BackfillTask{}
			}),
		},
		KV: &KVQuery{
			BridgeID: bridgeID,
			Database: db,
		},
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
