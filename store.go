package mautrix

import (
	"maunium.net/go/mautrix/event"
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
	SaveRoom(room *Room)
	LoadRoom(roomID id.RoomID) *Room
}

// InMemoryStore implements the Storer interface.
//
// Everything is persisted in-memory as maps. It is not safe to load/save filter IDs
// or next batch tokens on any goroutine other than the syncing goroutine: the one
// which called Client.Sync().
type InMemoryStore struct {
	Filters   map[id.UserID]string
	NextBatch map[id.UserID]string
	Rooms     map[id.RoomID]*Room
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

// SaveRoom to memory.
func (s *InMemoryStore) SaveRoom(room *Room) {
	s.Rooms[room.ID] = room
}

// LoadRoom from memory.
func (s *InMemoryStore) LoadRoom(roomID id.RoomID) *Room {
	return s.Rooms[roomID]
}

// UpdateState stores a state event. This can be passed to DefaultSyncer.OnEvent to keep all room state cached.
func (s *InMemoryStore) UpdateState(_ EventSource, evt *event.Event) {
	if !evt.Type.IsState() {
		return
	}
	room := s.LoadRoom(evt.RoomID)
	if room == nil {
		room = NewRoom(evt.RoomID)
		s.SaveRoom(room)
	}
	room.UpdateState(evt)
}

// NewInMemoryStore constructs a new InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		Filters:   make(map[id.UserID]string),
		NextBatch: make(map[id.UserID]string),
		Rooms:     make(map[id.RoomID]*Room),
	}
}
