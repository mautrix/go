// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package id

import (
	"errors"
	"fmt"
	"strings"
)

var InvalidContentURI = errors.New("invalid Matrix content URI")

type ContentURIString string

func (uriString ContentURIString) Parse() (ContentURI, error) {
	return ParseContentURI(string(uriString))
}

type ContentURI struct {
	Homeserver string
	FileID     string
}

func ParseContentURI(uri string) (parsed ContentURI, err error) {
	if !strings.HasPrefix(uri, "mxc://") {
		err = InvalidContentURI
	} else if index := strings.IndexRune(uri[6:], '/'); index == -1 || index == len(uri)-7 {
		err = InvalidContentURI
	} else {
		parsed.Homeserver = uri[6 : 6+index]
		parsed.FileID = uri[6+index+1:]
	}
	return
}

func (uri *ContentURI) UnmarshalJSON(raw []byte) (err error) {
	parsed, err := ParseContentURI(string(raw))
	if err != nil {
		return err
	}
	*uri = parsed
	return nil
}

func (uri *ContentURI) MarshalJSON() ([]byte, error) {
	return []byte(uri.String()), nil
}

func (uri *ContentURI) String() string {
	return fmt.Sprintf("mxc://%s/%s", uri.Homeserver, uri.FileID)
}

func (uri *ContentURI) CUString() ContentURIString {
	return ContentURIString(uri.String())
}

func (uri *ContentURI) IsEmpty() bool {
	return len(uri.Homeserver) == 0 || len(uri.FileID) == 0
}