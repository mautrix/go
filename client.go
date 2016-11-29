package gomatrix

import (
	"net/http"
	"net/url"
	"sync"
)

// Client represents a Matrix client.
type Client struct {
	HomeserverURL   *url.URL        // The base homeserver URL
	Prefix          string          // The API prefix eg '/_matrix/client/r0'
	UserID          string          // The user ID of the client. Used for forming HTTP paths which use the client's user ID.
	AccessToken     string          // The access_token for the client.
	syncingMutex    sync.Mutex      // protects syncingID
	syncingID       uint32          // Identifies the current Sync. Only one Sync can be active at any given time.
	Client          *http.Client    // The underlying HTTP client which will be used to make HTTP requests.
	FilterStorer    FilterStorer    // Interface for saving and loading the filter ID for sync.
	NextBatchStorer NextBatchStorer // Interface for saving and loading the "next_batch" sync token.
	// TODO: Worker and Rooms
}

// NewClient creates a new Matrix Client ready for syncing
func NewClient(httpClient *http.Client, homeserverURL *url.URL, accessToken, userID string) *Client {
	cli := Client{
		AccessToken:   accessToken,
		HomeserverURL: homeserverURL,
		UserID:        userID,
		Prefix:        "/_matrix/client/r0",
	}
	// By default, use a no-op next_batch storer which will never save tokens and always
	// "load" the empty string as a token. The client will work with this storer: it just won't
	// remember the token across restarts. In practice, a database backend should be used.
	cli.NextBatchStorer = NopNextBatchStore{}
	// By default, use a no-op filter storer which will never save the filter ID and always
	// "load" nothing. The client will work with this storer: it just won't remember the filter
	// ID across restarts and hence request a new one. In practice, a database backend should be used.
	cli.FilterStorer = NopFilterStore{}
	cli.Client = httpClient

	return &cli
}
