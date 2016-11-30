// Package gomatrix implements the Matrix Client-Server API.
//
// Specification can be found at http://matrix.org/docs/spec/client_server/r0.2.0.html
package gomatrix

import (
	"net/http"
	"net/url"
	"path"
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

// BuildURL builds a URL with the Client's homserver/prefix/access_token set already.
func (cli *Client) BuildURL(urlPath ...string) string {
	ps := []string{cli.Prefix}
	for _, p := range urlPath {
		ps = append(ps, p)
	}
	return cli.BuildBaseURL(ps...)
}

// BuildBaseURL builds a URL with the Client's homeserver/access_token set already. You must
// supply the prefix in the path.
func (cli *Client) BuildBaseURL(urlPath ...string) string {
	// copy the URL. Purposefully ignore error as the input is from a valid URL already
	hsURL, _ := url.Parse(cli.HomeserverURL.String())
	parts := []string{hsURL.Path}
	parts = append(parts, urlPath...)
	hsURL.Path = path.Join(parts...)
	query := hsURL.Query()
	query.Set("access_token", cli.AccessToken)
	hsURL.RawQuery = query.Encode()
	return hsURL.String()
}

// BuildURLWithQuery builds a URL with query paramters in addition to the Client's homeserver/prefix/access_token set already.
func (cli *Client) BuildURLWithQuery(urlPath []string, urlQuery map[string]string) string {
	u, _ := url.Parse(cli.BuildURL(urlPath...))
	q := u.Query()
	for k, v := range urlQuery {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// NewClient creates a new Matrix Client ready for syncing
func NewClient(homeserverURL, userID, accessToken string) (*Client, error) {
	hsURL, err := url.Parse(homeserverURL)
	if err != nil {
		return nil, err
	}
	cli := Client{
		AccessToken:   accessToken,
		HomeserverURL: hsURL,
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
	// By default, use the default HTTP client.
	cli.Client = http.DefaultClient

	return &cli, nil
}
