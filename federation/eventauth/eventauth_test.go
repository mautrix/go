// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build goexperiment.jsonv2

package eventauth_test

import (
	"embed"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix/federation/eventauth"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

//go:embed *.jsonl
var data embed.FS

type eventMap map[id.EventID]*pdu.PDU

func (em eventMap) Get(ids []id.EventID) ([]*pdu.PDU, error) {
	output := make([]*pdu.PDU, len(ids))
	for i, evtID := range ids {
		output[i] = em[evtID]
	}
	return output, nil
}

func GetKey(serverName string, keyID id.KeyID, validUntilTS time.Time) (id.SigningKey, time.Time, error) {
	return "", time.Time{}, nil
}

func TestAuthorize(t *testing.T) {
	files := exerrors.Must(data.ReadDir("."))
	for _, file := range files {
		t.Run(file.Name(), func(t *testing.T) {
			decoder := jsontext.NewDecoder(exerrors.Must(data.Open(file.Name())))
			events := make(eventMap)
			var roomVersion *id.RoomVersion
			for i := 1; ; i++ {
				var evt *pdu.PDU
				err := json.UnmarshalDecode(decoder, &evt)
				if errors.Is(err, io.EOF) {
					break
				}
				require.NoError(t, err)
				if roomVersion == nil {
					require.Equal(t, evt.Type, "m.room.create")
					roomVersion = ptr.Ptr(id.RoomVersion(gjson.GetBytes(evt.Content, "room_version").Str))
				}
				expectedEventID := gjson.GetBytes(evt.Unsigned, "event_id").Str
				evtID, err := evt.GetEventID(*roomVersion)
				require.NoError(t, err)
				require.Equalf(t, id.EventID(expectedEventID), evtID, "Event ID mismatch for event #%d", i)

				// TODO allow redacted events
				assert.True(t, evt.VerifyContentHash(), i)

				events[evtID] = evt
				err = eventauth.Authorize(*roomVersion, evt, events.Get, GetKey)
				if err != nil {
					evt.InternalMeta.Rejected = true
				}
				// TODO allow testing intentionally rejected events
				assert.NoErrorf(t, err, "Failed to authorize event #%d / %s of type %s", i, evtID, evt.Type)
			}
		})
	}

}
