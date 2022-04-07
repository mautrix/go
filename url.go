// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func parseAndNormalizeBaseURL(homeserverURL string) (*url.URL, error) {
	hsURL, err := url.Parse(homeserverURL)
	if err != nil {
		return nil, err
	}
	if hsURL.Scheme == "" {
		hsURL.Scheme = "https"
		fixedURL := hsURL.String()
		hsURL, err = url.Parse(fixedURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse fixed URL '%s': %v", fixedURL, err)
		}
	}
	hsURL.RawPath = hsURL.EscapedPath()
	return hsURL, nil
}

// BuildURL builds a URL with the given path parts
func BuildURL(baseURL *url.URL, path ...interface{}) *url.URL {
	createdURL := *baseURL
	rawParts := make([]string, len(path)+1)
	rawParts[0] = strings.TrimSuffix(createdURL.RawPath, "/")
	parts := make([]string, len(path)+1)
	parts[0] = strings.TrimSuffix(createdURL.Path, "/")
	for i, part := range path {
		switch casted := part.(type) {
		case string:
			parts[i+1] = casted
		case int:
			parts[i+1] = strconv.Itoa(casted)
		case Stringifiable:
			parts[i+1] = casted.String()
		default:
			parts[i+1] = fmt.Sprint(casted)
		}
		rawParts[i+1] = url.PathEscape(parts[i+1])
	}
	createdURL.Path = strings.Join(parts, "/")
	createdURL.RawPath = strings.Join(rawParts, "/")
	return &createdURL
}

// BuildURL builds a URL with the Client's homeserver and appservice user ID set already.
func (cli *Client) BuildURL(urlPath ...interface{}) string {
	return cli.BuildBaseURL(append(cli.Prefix, urlPath...)...)
}

// BuildBaseURL builds a URL with the Client's homeserver and appservice user ID set already.
// You must supply the prefix in the path.
func (cli *Client) BuildBaseURL(urlPath ...interface{}) string {
	return cli.BuildBaseURLWithQuery(urlPath, nil)
}

type URLPath = []interface{}

// BuildURLWithQuery builds a URL with query parameters in addition to the Client's
// homeserver and appservice user ID set already.
func (cli *Client) BuildURLWithQuery(urlPath URLPath, urlQuery map[string]string) string {
	return cli.BuildBaseURLWithQuery(append(cli.Prefix, urlPath...), urlQuery)
}

// BuildBaseURLWithQuery builds a URL with query parameters in addition to the Client's homeserver
// and appservice user ID set already. You must supply the prefix in the path.
func (cli *Client) BuildBaseURLWithQuery(urlPath URLPath, urlQuery map[string]string) string {
	hsURL := *BuildURL(cli.HomeserverURL, urlPath...)
	query := hsURL.Query()
	if cli.AppServiceUserID != "" {
		query.Set("user_id", string(cli.AppServiceUserID))
	}
	if urlQuery != nil {
		for k, v := range urlQuery {
			query.Set(k, v)
		}
	}
	hsURL.RawQuery = query.Encode()
	return hsURL.String()
}
