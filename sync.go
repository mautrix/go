package gomatrix

// NextBatchStorer controls loading/saving of next_batch tokens for users
type NextBatchStorer interface {
	// Save a next_batch token for a given user. Best effort.
	Save(userID, nextBatch string)
	// Load a next_batch token for a given user. Return an empty string if no token exists.
	Load(userID string) string
}

// NopNextBatchStore does not load or save next_batch tokens.
type NopNextBatchStore struct{}

// Save does nothing
func (s NopNextBatchStore) Save(userID, nextBatch string) {}

// Load does nothing
func (s NopNextBatchStore) Load(userID string) string { return "" }

// FilterStorer controls loading/saving of filter IDs for users
type FilterStorer interface {
	// Save a filter ID for a given user. Best effort.
	Save(userID, filterID string)
	// Load a filter ID for a given user. Return an empty string if no token exists.
	Load(userID string) string
}

// NopFilterStore does not load or save filter IDs.
type NopFilterStore struct{}

// Save does nothing
func (s NopFilterStore) Save(userID, filterID string) {}

// Load does nothing
func (s NopFilterStore) Load(userID string) string { return "" }
