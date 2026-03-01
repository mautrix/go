// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/event"
)

func TestPowerLevelsEventContent_EphemeralDefaultFallsBackToEventsDefault(t *testing.T) {
	pl := &event.PowerLevelsEventContent{
		EventsDefault: 45,
	}

	assert.Equal(t, 45, pl.EphemeralDefault())

	override := 60
	pl.EphemeralDefaultPtr = &override
	assert.Equal(t, 60, pl.EphemeralDefault())
}

func TestPowerLevelsEventContent_GetSetEphemeralLevel(t *testing.T) {
	pl := &event.PowerLevelsEventContent{
		EventsDefault: 25,
	}
	evtType := event.Type{Type: "com.example.ephemeral", Class: event.EphemeralEventType}

	assert.Equal(t, 25, pl.GetEphemeralLevel(evtType))

	pl.SetEphemeralLevel(evtType, 50)
	assert.Equal(t, 50, pl.GetEphemeralLevel(evtType))
	require.NotNil(t, pl.Ephemeral)
	assert.Equal(t, 50, pl.Ephemeral[evtType.String()])

	pl.SetEphemeralLevel(evtType, 25)
	_, exists := pl.Ephemeral[evtType.String()]
	assert.False(t, exists)
}

func TestPowerLevelsEventContent_CloneCopiesEphemeralFields(t *testing.T) {
	override := 70
	pl := &event.PowerLevelsEventContent{
		EventsDefault:       35,
		Ephemeral:           map[string]int{"com.example.ephemeral": 90},
		EphemeralDefaultPtr: &override,
	}

	cloned := pl.Clone()
	require.NotNil(t, cloned)
	require.NotNil(t, cloned.EphemeralDefaultPtr)
	assert.Equal(t, 70, *cloned.EphemeralDefaultPtr)
	assert.Equal(t, 90, cloned.Ephemeral["com.example.ephemeral"])

	cloned.Ephemeral["com.example.ephemeral"] = 99
	*cloned.EphemeralDefaultPtr = 71

	assert.Equal(t, 90, pl.Ephemeral["com.example.ephemeral"])
	assert.Equal(t, 70, *pl.EphemeralDefaultPtr)
}
