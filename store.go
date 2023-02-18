package mautrix

import (
	"maunium.net/go/mautrix/id"
)

// Storer is an interface which must be satisfied to store client data.
//
// You can either write a struct which persists this data to disk, or you can use the
// provided "InMemoryStore" which just keeps data around in-memory which is lost on
// restarts.
type Storer interface {
	SaveFilterID(userID id.UserID, filterID string)
	LoadFilterID(userID id.UserID) string
	SaveNextBatch(userID id.UserID, nextBatchToken string)
	LoadNextBatch(userID id.UserID) string
}

// InMemoryStore implements the Storer interface.
//
// Everything is persisted in-memory as maps. It is not safe to load/save filter IDs
// or next batch tokens on any goroutine other than the syncing goroutine: the one
// which called Client.Sync().
type InMemoryStore struct {
	Filters   map[id.UserID]string
	NextBatch map[id.UserID]string
}

// SaveFilterID to memory.
func (s *InMemoryStore) SaveFilterID(userID id.UserID, filterID string) {
	s.Filters[userID] = filterID
}

// LoadFilterID from memory.
func (s *InMemoryStore) LoadFilterID(userID id.UserID) string {
	return s.Filters[userID]
}

// SaveNextBatch to memory.
func (s *InMemoryStore) SaveNextBatch(userID id.UserID, nextBatchToken string) {
	s.NextBatch[userID] = nextBatchToken
}

// LoadNextBatch from memory.
func (s *InMemoryStore) LoadNextBatch(userID id.UserID) string {
	return s.NextBatch[userID]
}

// NewInMemoryStore constructs a new InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		Filters:   make(map[id.UserID]string),
		NextBatch: make(map[id.UserID]string),
	}
}

// AccountDataStore uses account data to store the next batch token, and
// reuses the InMemoryStore for all other operations.
type AccountDataStore struct {
	*InMemoryStore
	eventType string
	client    *Client
}

type accountData struct {
	NextBatch string `json:"next_batch"`
}

// SaveNextBatch to account data.
func (s *AccountDataStore) SaveNextBatch(userID id.UserID, nextBatchToken string) {
	if userID.String() != s.client.UserID.String() {
		panic("AccountDataStore must only be used with bots")
	}

	data := accountData{
		NextBatch: nextBatchToken,
	}

	err := s.client.SetAccountData(s.eventType, data)
	if err != nil {
		if s.client.Logger != nil {
			s.client.Logger.Debugfln("failed to save next batch token to account data: %s", err.Error())
		}
	}
}

// LoadNextBatch from account data.
func (s *AccountDataStore) LoadNextBatch(userID id.UserID) string {
	if userID.String() != s.client.UserID.String() {
		panic("AccountDataStore must only be used with bots")
	}

	data := &accountData{}

	err := s.client.GetAccountData(s.eventType, data)
	if err != nil {
		if s.client.Logger != nil {
			s.client.Logger.Debugfln("failed to load next batch token to account data: %s", err.Error())
		}
		return ""
	}

	return data.NextBatch
}

// NewAccountDataStore returns a new AccountDataStore, which stores
// the next_batch token as a custom event in account data in the
// homeserver.
//
// AccountDataStore is only appropriate for bots, not appservices.
//
// eventType should be a reversed DNS name like tld.domain.sub.internal and
// must be unique for a client. The data stored in it is considered internal
// and must not be modified through outside means. You should also add a filter
// for account data changes of this event type, to avoid ending up in a sync
// loop:
//
//	mautrix.Filter{
//		AccountData: mautrix.FilterPart{
//			Limit: 20,
//			NotTypes: []event.Type{
//				event.NewEventType(eventType),
//			},
//		},
//	}
//	mautrix.Client.CreateFilter(...)
func NewAccountDataStore(eventType string, client *Client) *AccountDataStore {
	return &AccountDataStore{
		InMemoryStore: NewInMemoryStore(),
		eventType:     eventType,
		client:        client,
	}
}
