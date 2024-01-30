// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package id_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/element-hq/mautrix-go/id"
)

var (
	roomIDLink         = id.MatrixURI{Sigil1: '!', MXID1: "7NdBVvkd4aLSbgKt9RXl:example.org"}
	roomIDViaLink      = id.MatrixURI{Sigil1: '!', MXID1: "7NdBVvkd4aLSbgKt9RXl:example.org", Via: []string{"maunium.net", "matrix.org"}}
	roomAliasLink      = id.MatrixURI{Sigil1: '#', MXID1: "someroom:example.org"}
	roomIDEventLink    = id.MatrixURI{Sigil1: '!', MXID1: "7NdBVvkd4aLSbgKt9RXl:example.org", Sigil2: '$', MXID2: "uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s"}
	roomAliasEventLink = id.MatrixURI{Sigil1: '#', MXID1: "someroom:example.org", Sigil2: '$', MXID2: "uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s"}
	userLink           = id.MatrixURI{Sigil1: '@', MXID1: "user:example.org"}

	escapeRoomIDEventLink = id.MatrixURI{Sigil1: '!', MXID1: "meow & 🐈️:example.org", Sigil2: '$', MXID2: "uOH4C9cK4HhMeFWkUXMbdF/dtndJ0j9je+kIK3XpV1s"}
)

func TestMatrixURI_MatrixToURL(t *testing.T) {
	assert.Equal(t, "https://matrix.to/#/%217NdBVvkd4aLSbgKt9RXl:example.org", roomIDLink.MatrixToURL())
	assert.Equal(t, "https://matrix.to/#/%217NdBVvkd4aLSbgKt9RXl:example.org?via=maunium.net&via=matrix.org", roomIDViaLink.MatrixToURL())
	assert.Equal(t, "https://matrix.to/#/%23someroom:example.org", roomAliasLink.MatrixToURL())
	assert.Equal(t, "https://matrix.to/#/%217NdBVvkd4aLSbgKt9RXl:example.org/$uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s", roomIDEventLink.MatrixToURL())
	assert.Equal(t, "https://matrix.to/#/%23someroom:example.org/$uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s", roomAliasEventLink.MatrixToURL())
	assert.Equal(t, "https://matrix.to/#/@user:example.org", userLink.MatrixToURL())
	assert.Equal(t, "https://matrix.to/#/%21meow%20&%20%F0%9F%90%88%EF%B8%8F:example.org/$uOH4C9cK4HhMeFWkUXMbdF%2FdtndJ0j9je+kIK3XpV1s", escapeRoomIDEventLink.MatrixToURL())
}

func TestMatrixURI_String(t *testing.T) {
	assert.Equal(t, "matrix:roomid/7NdBVvkd4aLSbgKt9RXl:example.org", roomIDLink.String())
	assert.Equal(t, "matrix:roomid/7NdBVvkd4aLSbgKt9RXl:example.org?via=maunium.net&via=matrix.org", roomIDViaLink.String())
	assert.Equal(t, "matrix:r/someroom:example.org", roomAliasLink.String())
	assert.Equal(t, "matrix:roomid/7NdBVvkd4aLSbgKt9RXl:example.org/e/uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s", roomIDEventLink.String())
	assert.Equal(t, "matrix:r/someroom:example.org/e/uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s", roomAliasEventLink.String())
	assert.Equal(t, "matrix:u/user:example.org", userLink.String())
	assert.Equal(t, "matrix:roomid/meow%20&%20%F0%9F%90%88%EF%B8%8F:example.org/e/uOH4C9cK4HhMeFWkUXMbdF%2FdtndJ0j9je+kIK3XpV1s", escapeRoomIDEventLink.String())
}

func TestParseMatrixURIOrMatrixToURL(t *testing.T) {
	const inputURI = "matrix:u/user:example.org"
	const inputMatrixToURL = "https://matrix.to/#/@user:example.org"
	parsed1, err := id.ParseMatrixURIOrMatrixToURL(inputURI)
	require.NoError(t, err)
	require.NotNil(t, parsed1)
	parsed2, err := id.ParseMatrixURIOrMatrixToURL(inputMatrixToURL)
	require.NoError(t, err)
	require.NotNil(t, parsed2)

	assert.Equal(t, parsed1, parsed2)
	assert.Equal(t, inputURI, parsed2.String())
	assert.Equal(t, inputMatrixToURL, parsed1.MatrixToURL())
}

func TestParseMatrixURI_RoomAlias(t *testing.T) {
	parsed1, err := id.ParseMatrixURI("matrix:r/someroom:example.org")
	require.NoError(t, err)
	require.NotNil(t, parsed1)
	parsed2, err := id.ParseMatrixURI("matrix:room/someroom:example.org")
	require.NoError(t, err)
	require.NotNil(t, parsed2)

	assert.Equal(t, roomAliasLink, *parsed1)
	assert.Equal(t, roomAliasLink, *parsed2)
}

func TestParseMatrixURI_RoomID(t *testing.T) {
	parsed, err := id.ParseMatrixURI("matrix:roomid/7NdBVvkd4aLSbgKt9RXl:example.org")
	require.NoError(t, err)
	require.NotNil(t, parsed)
	parsedVia, err := id.ParseMatrixURI("matrix:roomid/7NdBVvkd4aLSbgKt9RXl:example.org?via=maunium.net&via=matrix.org")
	require.NoError(t, err)
	require.NotNil(t, parsedVia)

	assert.Equal(t, roomIDLink, *parsed)
	assert.Equal(t, roomIDViaLink, *parsedVia)
}

func TestParseMatrixURI_UserID(t *testing.T) {
	parsed1, err := id.ParseMatrixURI("matrix:u/user:example.org")
	require.NoError(t, err)
	require.NotNil(t, parsed1)
	parsed2, err := id.ParseMatrixURI("matrix:user/user:example.org")
	require.NoError(t, err)
	require.NotNil(t, parsed2)

	assert.Equal(t, userLink, *parsed1)
	assert.Equal(t, userLink, *parsed2)
}

func TestParseMatrixURI_EventID(t *testing.T) {
	parsed1, err := id.ParseMatrixURI("matrix:r/someroom:example.org/e/uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s")
	require.NoError(t, err)
	require.NotNil(t, parsed1)
	parsed2, err := id.ParseMatrixURI("matrix:room/someroom:example.org/e/uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s")
	require.NoError(t, err)
	require.NotNil(t, parsed2)
	parsed3, err := id.ParseMatrixURI("matrix:roomid/7NdBVvkd4aLSbgKt9RXl:example.org/e/uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s")
	require.NoError(t, err)
	require.NotNil(t, parsed3)

	assert.Equal(t, roomAliasEventLink, *parsed1)
	assert.Equal(t, roomAliasEventLink, *parsed2)
	assert.Equal(t, roomIDEventLink, *parsed3)
}

func TestParseMatrixToURL_RoomAlias(t *testing.T) {
	parsed, err := id.ParseMatrixToURL("https://matrix.to/#/#someroom:example.org")
	require.NoError(t, err)
	require.NotNil(t, parsed)
	parsedEncoded, err := id.ParseMatrixToURL("https://matrix.to/#/%23someroom%3Aexample.org")
	require.NoError(t, err)
	require.NotNil(t, parsedEncoded)

	assert.Equal(t, roomAliasLink, *parsed)
	assert.Equal(t, roomAliasLink, *parsedEncoded)
}

func TestParseMatrixToURL_RoomID(t *testing.T) {
	parsed, err := id.ParseMatrixToURL("https://matrix.to/#/!7NdBVvkd4aLSbgKt9RXl:example.org")
	require.NoError(t, err)
	require.NotNil(t, parsed)
	parsedEncoded, err := id.ParseMatrixToURL("https://matrix.to/#/%217NdBVvkd4aLSbgKt9RXl%3Aexample.org")
	require.NoError(t, err)
	require.NotNil(t, parsedEncoded)
	parsedVia, err := id.ParseMatrixToURL("https://matrix.to/#/!7NdBVvkd4aLSbgKt9RXl:example.org?via=maunium.net&via=matrix.org")
	require.NoError(t, err)
	require.NotNil(t, parsedVia)
	parsedViaEncoded, err := id.ParseMatrixToURL("https://matrix.to/#/%217NdBVvkd4aLSbgKt9RXl%3Aexample.org?via=maunium.net&via=matrix.org")
	require.NoError(t, err)
	require.NotNil(t, parsedViaEncoded)

	assert.Equal(t, roomIDLink, *parsed)
	assert.Equal(t, roomIDLink, *parsedEncoded)
	assert.Equal(t, roomIDViaLink, *parsedVia)
	assert.Equal(t, roomIDViaLink, *parsedViaEncoded)
}

func TestParseMatrixToURL_UserID(t *testing.T) {
	parsed, err := id.ParseMatrixToURL("https://matrix.to/#/@user:example.org")
	require.NoError(t, err)
	require.NotNil(t, parsed)
	parsedEncoded, err := id.ParseMatrixToURL("https://matrix.to/#/%40user%3Aexample.org")
	require.NoError(t, err)
	require.NotNil(t, parsedEncoded)

	assert.Equal(t, userLink, *parsed)
	assert.Equal(t, userLink, *parsedEncoded)
}

func TestParseMatrixToURL_EventID(t *testing.T) {
	parsed1, err := id.ParseMatrixToURL("https://matrix.to/#/#someroom:example.org/$uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s")
	require.NoError(t, err)
	require.NotNil(t, parsed1)
	parsed2, err := id.ParseMatrixToURL("https://matrix.to/#/!7NdBVvkd4aLSbgKt9RXl:example.org/$uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s")
	require.NoError(t, err)
	require.NotNil(t, parsed2)
	parsed1Encoded, err := id.ParseMatrixToURL("https://matrix.to/#/%23someroom:example.org/%24uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s")
	require.NoError(t, err)
	require.NotNil(t, parsed1)
	parsed2Encoded, err := id.ParseMatrixToURL("https://matrix.to/#/%217NdBVvkd4aLSbgKt9RXl:example.org/%24uOH4C9cK4HhMeFWkUXMbdF_dtndJ0j9je-kIK3XpV1s")
	require.NoError(t, err)
	require.NotNil(t, parsed2)

	assert.Equal(t, roomAliasEventLink, *parsed1)
	assert.Equal(t, roomAliasEventLink, *parsed1Encoded)
	assert.Equal(t, roomIDEventLink, *parsed2)
	assert.Equal(t, roomIDEventLink, *parsed2Encoded)
}
