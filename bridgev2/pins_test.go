// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"testing"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

func TestApplyPinnedEventDelta(t *testing.T) {
	tests := []struct {
		name     string
		current  []id.EventID
		pinned   []id.EventID
		unpinned []id.EventID
		expected []id.EventID
	}{
		{
			name:     "pin into empty list",
			pinned:   []id.EventID{"$a"},
			expected: []id.EventID{"$a"},
		},
		{
			name:     "pin is prepended",
			current:  []id.EventID{"$a"},
			pinned:   []id.EventID{"$b"},
			expected: []id.EventID{"$b", "$a"},
		},
		{
			name:     "unpin keeps the others",
			current:  []id.EventID{"$b", "$a"},
			unpinned: []id.EventID{"$b"},
			expected: []id.EventID{"$a"},
		},
		{
			name:     "unpin unknown event is a no-op",
			current:  []id.EventID{"$a"},
			unpinned: []id.EventID{"$zzz"},
			expected: []id.EventID{"$a"},
		},
		{
			name:     "re-pinning an already pinned event doesn't duplicate it",
			current:  []id.EventID{"$a", "$b"},
			pinned:   []id.EventID{"$b"},
			expected: []id.EventID{"$b", "$a"},
		},
		{
			name:     "pin and unpin in the same delta",
			current:  []id.EventID{"$a", "$b"},
			pinned:   []id.EventID{"$c"},
			unpinned: []id.EventID{"$a"},
			expected: []id.EventID{"$c", "$b"},
		},
		{
			name:     "unpin everything",
			current:  []id.EventID{"$a", "$b"},
			unpinned: []id.EventID{"$a", "$b"},
			expected: []id.EventID{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := applyPinnedEventDelta(test.current, test.pinned, test.unpinned)
			if len(got) != len(test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, got)
			}
			for i := range got {
				if got[i] != test.expected[i] {
					t.Fatalf("expected %v, got %v", test.expected, got)
				}
			}
		})
	}
}

func msg(id networkid.MessageID) *database.Message {
	return &database.Message{ID: id}
}

func msgIDs(messages []*database.Message) []networkid.MessageID {
	ids := make([]networkid.MessageID, len(messages))
	for i, m := range messages {
		ids[i] = m.ID
	}
	return ids
}

func TestDiffPinnedMessages(t *testing.T) {
	tests := []struct {
		name           string
		old, new       []*database.Message
		added, removed []networkid.MessageID
	}{
		{
			name:  "first pin",
			new:   []*database.Message{msg("1")},
			added: []networkid.MessageID{"1"},
		},
		{
			name:    "unpin",
			old:     []*database.Message{msg("1")},
			removed: []networkid.MessageID{"1"},
		},
		{
			name: "no change",
			old:  []*database.Message{msg("1"), msg("2")},
			new:  []*database.Message{msg("1"), msg("2")},
		},
		{
			name: "reorder only is not a change",
			old:  []*database.Message{msg("1"), msg("2")},
			new:  []*database.Message{msg("2"), msg("1")},
		},
		{
			name:    "pin one, unpin another",
			old:     []*database.Message{msg("1"), msg("2")},
			new:     []*database.Message{msg("2"), msg("3")},
			added:   []networkid.MessageID{"3"},
			removed: []networkid.MessageID{"1"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			added, removed := diffPinnedMessages(test.old, test.new)
			gotAdded, gotRemoved := msgIDs(added), msgIDs(removed)
			if len(gotAdded) != len(test.added) {
				t.Fatalf("expected added %v, got %v", test.added, gotAdded)
			}
			for i := range gotAdded {
				if gotAdded[i] != test.added[i] {
					t.Fatalf("expected added %v, got %v", test.added, gotAdded)
				}
			}
			if len(gotRemoved) != len(test.removed) {
				t.Fatalf("expected removed %v, got %v", test.removed, gotRemoved)
			}
			for i := range gotRemoved {
				if gotRemoved[i] != test.removed[i] {
					t.Fatalf("expected removed %v, got %v", test.removed, gotRemoved)
				}
			}
		})
	}
}
