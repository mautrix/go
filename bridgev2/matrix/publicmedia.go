// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/id"
)

var _ bridgev2.MatrixConnectorWithPublicMedia = (*Connector)(nil)

func (br *Connector) initPublicMedia() error {
	if !br.Config.PublicMedia.Enabled {
		return nil
	} else if br.GetPublicAddress() == "" {
		return fmt.Errorf("public media is enabled in config, but no public address is set")
	} else if br.Config.PublicMedia.HashLength > 32 {
		return fmt.Errorf("public media hash length is too long")
	} else if br.Config.PublicMedia.HashLength < 0 {
		return fmt.Errorf("public media hash length is negative")
	}
	br.pubMediaSigKey = []byte(br.Config.PublicMedia.SigningKey)
	br.AS.Router.HandleFunc("GET /_mautrix/publicmedia/{server}/{mediaID}/{checksum}", br.servePublicMedia)
	return nil
}

func (br *Connector) hashContentURI(uri id.ContentURI, expiry []byte) []byte {
	hasher := hmac.New(sha256.New, br.pubMediaSigKey)
	hasher.Write([]byte(uri.String()))
	hasher.Write(expiry)
	return hasher.Sum(expiry)[:br.Config.PublicMedia.HashLength+len(expiry)]
}

func (br *Connector) makePublicMediaChecksum(uri id.ContentURI) []byte {
	var expiresAt []byte
	if br.Config.PublicMedia.Expiry > 0 {
		expiresAtInt := time.Now().Add(time.Duration(br.Config.PublicMedia.Expiry) * time.Second).Unix()
		expiresAt = binary.BigEndian.AppendUint64(nil, uint64(expiresAtInt))
	}
	return br.hashContentURI(uri, expiresAt)
}

func (br *Connector) verifyPublicMediaChecksum(uri id.ContentURI, checksum []byte) (valid, expired bool) {
	var expiryBytes []byte
	if br.Config.PublicMedia.Expiry > 0 {
		if len(checksum) < 8 {
			return
		}
		expiryBytes = checksum[:8]
		expiresAtInt := binary.BigEndian.Uint64(expiryBytes)
		expired = time.Now().Unix() > int64(expiresAtInt)
	}
	valid = hmac.Equal(checksum, br.hashContentURI(uri, expiryBytes))
	return
}

var proxyHeadersToCopy = []string{
	"Content-Type", "Content-Disposition", "Content-Length", "Content-Security-Policy",
	"Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers",
	"Cache-Control", "Cross-Origin-Resource-Policy",
}

func (br *Connector) servePublicMedia(w http.ResponseWriter, r *http.Request) {
	contentURI := id.ContentURI{
		Homeserver: r.PathValue("server"),
		FileID:     r.PathValue("mediaID"),
	}
	if !contentURI.IsValid() {
		http.Error(w, "invalid content URI", http.StatusBadRequest)
		return
	}
	checksum, err := base64.RawURLEncoding.DecodeString(r.PathValue("checksum"))
	if err != nil || !hmac.Equal(checksum, br.makePublicMediaChecksum(contentURI)) {
		http.Error(w, "invalid base64 in checksum", http.StatusBadRequest)
		return
	} else if valid, expired := br.verifyPublicMediaChecksum(contentURI, checksum); !valid {
		http.Error(w, "invalid checksum", http.StatusNotFound)
		return
	} else if expired {
		http.Error(w, "checksum expired", http.StatusGone)
		return
	}
	resp, err := br.Bot.Download(r.Context(), contentURI)
	if err != nil {
		br.Log.Warn().Stringer("uri", contentURI).Err(err).Msg("Failed to download media to proxy")
		http.Error(w, "failed to download media", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	for _, hdr := range proxyHeadersToCopy {
		w.Header()[hdr] = resp.Header[hdr]
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

func (br *Connector) GetPublicMediaAddress(contentURI id.ContentURIString) string {
	if br.pubMediaSigKey == nil {
		return ""
	}
	parsed, err := contentURI.Parse()
	if err != nil || !parsed.IsValid() {
		return ""
	}
	return fmt.Sprintf(
		"%s/_mautrix/publicmedia/%s/%s/%s",
		br.GetPublicAddress(),
		parsed.Homeserver,
		parsed.FileID,
		base64.RawURLEncoding.EncodeToString(br.makePublicMediaChecksum(parsed)),
	)
}
