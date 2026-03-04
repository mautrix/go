// Copyright (c) 2026 Tulir Asokan
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

func TestPowerLevelsEventContent_BeeperEphemeralDefaultFallsBackToEventsDefault(t *testing.T) {
	pl := &event.PowerLevelsEventContent{
		EventsDefault: 45,
	}

	assert.Equal(t, 45, pl.BeeperEphemeralDefault())

	override := 60
	pl.BeeperEphemeralDefaultPtr = &override
	assert.Equal(t, 60, pl.BeeperEphemeralDefault())
}

func TestPowerLevelsEventContent_GetSetBeeperEphemeralLevel(t *testing.T) {
	pl := &event.PowerLevelsEventContent{
		EventsDefault: 25,
	}
	evtType := event.Type{Type: "com.example.ephemeral", Class: event.EphemeralEventType}

	assert.Equal(t, 25, pl.GetBeeperEphemeralLevel(evtType))

	pl.SetBeeperEphemeralLevel(evtType, 50)
	assert.Equal(t, 50, pl.GetBeeperEphemeralLevel(evtType))
	require.NotNil(t, pl.BeeperEphemeral)
	assert.Equal(t, 50, pl.BeeperEphemeral[evtType.String()])

	pl.SetBeeperEphemeralLevel(evtType, 25)
	_, exists := pl.BeeperEphemeral[evtType.String()]
	assert.False(t, exists)
}

func TestPowerLevelsEventContent_CloneCopiesBeeperEphemeralFields(t *testing.T) {
	override := 70
	pl := &event.PowerLevelsEventContent{
		EventsDefault:             35,
		BeeperEphemeral:           map[string]int{"com.example.ephemeral": 90},
		BeeperEphemeralDefaultPtr: &override,
	}

	cloned := pl.Clone()
	require.NotNil(t, cloned)
	require.NotNil(t, cloned.BeeperEphemeralDefaultPtr)
	assert.Equal(t, 70, *cloned.BeeperEphemeralDefaultPtr)
	assert.Equal(t, 90, cloned.BeeperEphemeral["com.example.ephemeral"])

	cloned.BeeperEphemeral["com.example.ephemeral"] = 99
	*cloned.BeeperEphemeralDefaultPtr = 71

	assert.Equal(t, 90, pl.BeeperEphemeral["com.example.ephemeral"])
	assert.Equal(t, 70, *pl.BeeperEphemeralDefaultPtr)
}
