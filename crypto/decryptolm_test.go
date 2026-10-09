// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"errors"
	"testing"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type blockedUnwedgeStore struct {
	Store
	started chan struct{}
	finish  chan struct{}
}

func (s *blockedUnwedgeStore) GetNewestSessionCreationTS(ctx context.Context, _ id.SenderKey) (time.Time, error) {
	s.started <- struct{}{}
	select {
	case <-s.finish:
	case <-ctx.Done():
	}
	return time.Time{}, errors.New("end test repair")
}

func TestWithUnwedgeWait(t *testing.T) {
	for _, cancelRepair := range []bool{false, true} {
		t.Run(map[bool]string{false: "completion", true: "cancellation"}[cancelRepair], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			mach := newMachine(t, "@test:example.org")
			defer mach.Destroy()
			store := &blockedUnwedgeStore{
				Store: mach.CryptoStore, started: make(chan struct{}, 1), finish: make(chan struct{}),
			}
			mach.CryptoStore = store
			scopedCtx, wait := WithUnwedgeWait(ctx)
			mach.HandleEncryptedEvent(scopedCtx, &event.Event{
				Sender: "@sender:example.org",
				Content: event.Content{Parsed: &event.EncryptedEventContent{
					Algorithm: id.AlgorithmOlmV1,
					SenderKey: "unknown",
					OlmCiphertext: event.OlmCiphertexts{
						mach.account.IdentityKey(): {Type: id.OlmMsgTypeMsg, Body: "AQID"},
					},
				}},
			})
			select {
			case <-store.started:
			case <-ctx.Done():
				t.Fatal("repair did not start")
			}
			done := make(chan struct{})
			go func() { wait(); close(done) }()
			defer func() { cancel(); <-done }()
			select {
			case <-done:
				t.Fatal("wait returned before repair finished")
			case <-time.After(30 * time.Millisecond):
			}

			_, waitForOtherScope := WithUnwedgeWait(ctx)
			waitForOtherScope()
			if cancelRepair {
				cancel()
			} else {
				close(store.finish)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("wait did not finish")
			}
		})
	}
}
