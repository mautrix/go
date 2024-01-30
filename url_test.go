// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/element-hq/mautrix-go"
)

func TestClient_BuildURL(t *testing.T) {
	cli, err := mautrix.NewClient("https://example.com", "", "")
	assert.NoError(t, err)
	assert.Equal(t, cli.HomeserverURL.Scheme, "https")
	assert.Equal(t, cli.HomeserverURL.Host, "example.com")
	assert.Equal(t, cli.HomeserverURL.Path, "")
	built := cli.BuildClientURL("v3", "foo/bar%2F🐈 1", "hello", "world")
	assert.Equal(t, "https://example.com/_matrix/client/v3/foo%2Fbar%252F%F0%9F%90%88%201/hello/world", built)
}

func TestClient_BuildURL_HTTP(t *testing.T) {
	cli, err := mautrix.NewClient("http://example.com", "", "")
	assert.NoError(t, err)
	assert.Equal(t, cli.HomeserverURL.Scheme, "http")
	assert.Equal(t, cli.HomeserverURL.Host, "example.com")
	assert.Equal(t, cli.HomeserverURL.Path, "")
	built := cli.BuildClientURL("v3", "foo/bar%2F🐈 1", "hello", "world")
	assert.Equal(t, "http://example.com/_matrix/client/v3/foo%2Fbar%252F%F0%9F%90%88%201/hello/world", built)
}

func TestClient_BuildURL_MissingScheme(t *testing.T) {
	cli, err := mautrix.NewClient("example.com", "", "")
	assert.NoError(t, err)
	assert.Equal(t, cli.HomeserverURL.Scheme, "https")
	assert.Equal(t, cli.HomeserverURL.Host, "example.com")
	assert.Equal(t, cli.HomeserverURL.Path, "")
	built := cli.BuildClientURL("v3", "foo/bar%2F🐈 1", "hello", "world")
	assert.Equal(t, "https://example.com/_matrix/client/v3/foo%2Fbar%252F%F0%9F%90%88%201/hello/world", built)
}

func TestClient_BuildURL_WithPath(t *testing.T) {
	cli, err := mautrix.NewClient("https://example.com/base", "", "")
	assert.NoError(t, err)
	assert.Equal(t, cli.HomeserverURL.Scheme, "https")
	assert.Equal(t, cli.HomeserverURL.Host, "example.com")
	assert.Equal(t, cli.HomeserverURL.Path, "/base")
	built := cli.BuildClientURL("v3", "foo/bar%2F🐈 1", "hello", "world")
	assert.Equal(t, "https://example.com/base/_matrix/client/v3/foo%2Fbar%252F%F0%9F%90%88%201/hello/world", built)
}

func TestClient_BuildURL_MissingSchemeWithPath(t *testing.T) {
	cli, err := mautrix.NewClient("example.com/base", "", "")
	assert.NoError(t, err)
	assert.Equal(t, cli.HomeserverURL.Scheme, "https")
	assert.Equal(t, cli.HomeserverURL.Host, "example.com")
	assert.Equal(t, cli.HomeserverURL.Path, "/base")
	built := cli.BuildClientURL("v3", "foo/bar%2F🐈 1", "hello", "world")
	assert.Equal(t, "https://example.com/base/_matrix/client/v3/foo%2Fbar%252F%F0%9F%90%88%201/hello/world", built)
}
