// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	"maunium.net/go/mautrix"
)

type FileMetadata struct {
	// Header contains the multipart or HTTP response headers for the file.
	// This is not parsed from the JSON metadata.
	Header http.Header `json:"-"`
	// JSON-parsed fields will be added once some are defined in the spec.
}

type mediaPartReader struct {
	respBody io.ReadCloser
	part     *multipart.Part
}

func (mpr *mediaPartReader) Read(p []byte) (n int, err error) {
	return mpr.part.Read(p)
}

func (mpr *mediaPartReader) Close() error {
	err1 := mpr.part.Close()
	err2 := mpr.respBody.Close()
	return cmp.Or(err1, err2)
}

func (c *Client) DownloadMedia(ctx context.Context, serverName, mediaID string) (meta *FileMetadata, data io.ReadCloser, err error) {
	_, resp, err := c.MakeFullRequest(ctx, RequestParams{
		ServerName:   serverName,
		Method:       http.MethodGet,
		Path:         URLPath{"v1", "media", "download", mediaID},
		Authenticate: true,
		DontReadBody: true,
	})
	if err != nil {
		return nil, nil, nil
	}
	defer func() {
		if data == nil {
			_ = resp.Body.Close()
		}
	}()
	mimeType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse content type: %w", err)
	} else if mimeType != "multipart/mixed" {
		return nil, nil, fmt.Errorf("unexpected content type: %s", mimeType)
	} else if params["boundary"] == "" {
		return nil, nil, fmt.Errorf("missing boundary parameter in content type")
	}
	mr := multipart.NewReader(resp.Body, params["boundary"])
	part, err := mr.NextPart()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read metadata chunk: %w", err)
	} else if !strings.HasPrefix(part.Header.Get("Content-Type"), "application/json") {
		_ = part.Close()
		return nil, nil, fmt.Errorf("unexpected content type for metadata chunk: %s", part.Header.Get("Content-Type"))
	}
	mbr := http.MaxBytesReader(nil, part, 64*1024)
	err = json.NewDecoder(mbr).Decode(&meta)
	_ = mbr.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse metadata: %w", err)
	}
	part, err = mr.NextPart()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read data chunk: %w", err)
	}
	redir := part.Header.Get("Location")
	if redir != "" {
		_ = resp.Body.Close()
		_ = part.Close()
		data, meta.Header, err = c.downloadMediaRedirect(ctx, redir)
		return
	}
	meta.Header = http.Header(part.Header)
	return meta, &mediaPartReader{
		respBody: resp.Body,
		part:     part,
	}, nil
}

func (c *Client) downloadMediaRedirect(ctx context.Context, url string) (io.ReadCloser, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare redirect request: %w", err)
	} else if req.URL.Scheme != "https" {
		return nil, nil, fmt.Errorf("non-https URL in redirect")
	}
	resp, err := c.ExtHTTP.Do(req)
	if err != nil {
		return nil, nil, mautrix.HTTPError{
			Request:  req,
			Response: resp,

			Message:      "media redirect request error",
			WrappedError: err,
		}
	} else if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, nil, fmt.Errorf("unexpected status code from redirect: %w", mautrix.HTTPError{
			Request:  req,
			Response: resp,
		})
	}
	return resp.Body, resp.Header, nil
}
