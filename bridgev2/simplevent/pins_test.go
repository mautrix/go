// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package simplevent

import (
	"testing"

	"maunium.net/go/mautrix/bridgev2/networkid"
)

func TestPinnedMessages_IsPinnedMessagesDelta(t *testing.T) {
	tests := []struct {
		name     string
		evt      PinnedMessages
		expected bool
	}{
		{
			name:     "pin delta",
			evt:      PinnedMessages{Pinned: []networkid.MessageID{"1"}},
			expected: true,
		},
		{
			name:     "unpin delta",
			evt:      PinnedMessages{Unpinned: []networkid.MessageID{"1"}},
			expected: true,
		},
		{
			name:     "full list",
			evt:      PinnedMessages{PinnedList: []networkid.MessageID{"1"}},
			expected: false,
		},
		{
			// This is how "everything was unpinned" is expressed: no delta, empty full list.
			name:     "empty event clears all pins",
			evt:      PinnedMessages{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.evt.IsPinnedMessagesDelta(); got != test.expected {
				t.Fatalf("expected %v, got %v", test.expected, got)
			}
			if !test.evt.IsPinnedMessagesDelta() {
				list, err := test.evt.GetPinnedMessages(t.Context())
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(list) != len(test.evt.PinnedList) {
					t.Fatalf("expected %v, got %v", test.evt.PinnedList, list)
				}
			}
		})
	}
}
