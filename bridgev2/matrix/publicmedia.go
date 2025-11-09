// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"
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
	br.AS.Router.HandleFunc("GET /_mautrix/publicmedia/{customID}", br.serveDatabasePublicMedia)
	br.AS.Router.HandleFunc("GET /_mautrix/publicmedia/{customID}/{filename}", br.serveDatabasePublicMedia)
	br.AS.Router.HandleFunc("GET /_mautrix/publicmedia/{server}/{mediaID}/{checksum}", br.servePublicMedia)
	br.AS.Router.HandleFunc("GET /_mautrix/publicmedia/{server}/{mediaID}/{checksum}/{filename}", br.servePublicMedia)
	return nil
}

func (br *Connector) hashContentURI(uri id.ContentURI, expiry []byte) []byte {
	hasher := hmac.New(sha256.New, br.pubMediaSigKey)
	hasher.Write([]byte(uri.String()))
	hasher.Write(expiry)
	return hasher.Sum(expiry)[:br.Config.PublicMedia.HashLength+len(expiry)]
}

func (br *Connector) hashDBPublicMedia(pm *database.PublicMedia) []byte {
	hasher := hmac.New(sha256.New, br.pubMediaSigKey)
	hasher.Write([]byte(pm.MXC.String()))
	hasher.Write([]byte(pm.MimeType))
	if pm.Keys != nil {
		hasher.Write([]byte(pm.Keys.Version))
		hasher.Write([]byte(pm.Keys.Key.Algorithm))
		hasher.Write([]byte(pm.Keys.Key.Key))
		hasher.Write([]byte(pm.Keys.InitVector))
		hasher.Write([]byte(pm.Keys.Hashes.SHA256))
	}
	return hasher.Sum(nil)[:br.Config.PublicMedia.HashLength]
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
	br.doProxyMedia(w, r, contentURI, nil, "")
}

func (br *Connector) serveDatabasePublicMedia(w http.ResponseWriter, r *http.Request) {
	if !br.Config.PublicMedia.UseDatabase {
		http.Error(w, "public media short links are disabled", http.StatusNotFound)
		return
	}
	log := zerolog.Ctx(r.Context())
	media, err := br.Bridge.DB.PublicMedia.Get(r.Context(), r.PathValue("customID"))
	if err != nil {
		log.Err(err).Msg("Failed to get public media from database")
		http.Error(w, "failed to get media metadata", http.StatusInternalServerError)
		return
	} else if media == nil {
		http.Error(w, "media ID not found", http.StatusNotFound)
		return
	} else if !media.Expiry.IsZero() && media.Expiry.Before(time.Now()) {
		// This is not gone as it can still be refreshed in the DB
		http.Error(w, "media expired", http.StatusNotFound)
		return
	} else if media.Keys != nil && media.Keys.PrepareForDecryption() != nil {
		http.Error(w, "media keys are malformed", http.StatusInternalServerError)
		return
	}
	br.doProxyMedia(w, r, media.MXC, media.Keys, media.MimeType)
}

var safeMimes = []string{
	"text/css", "text/plain", "text/csv",
	"application/json", "application/ld+json",
	"image/jpeg", "image/gif", "image/png", "image/apng", "image/webp", "image/avif",
	"video/mp4", "video/webm", "video/ogg", "video/quicktime",
	"audio/mp4", "audio/webm", "audio/aac", "audio/mpeg", "audio/ogg", "audio/wave",
	"audio/wav", "audio/x-wav", "audio/x-pn-wav", "audio/flac", "audio/x-flac",
}

func (br *Connector) doProxyMedia(w http.ResponseWriter, r *http.Request, contentURI id.ContentURI, encInfo *attachment.EncryptedFile, mimeType string) {
	resp, err := br.Bot.Download(r.Context(), contentURI)
	if err != nil {
		zerolog.Ctx(r.Context()).Warn().Stringer("uri", contentURI).Err(err).Msg("Failed to download media to proxy")
		http.Error(w, "failed to download media", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	for _, hdr := range proxyHeadersToCopy {
		w.Header()[hdr] = resp.Header[hdr]
	}
	stream := resp.Body
	if encInfo != nil {
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}
		contentDisposition := "attachment"
		if slices.Contains(safeMimes, mimeType) {
			contentDisposition = "inline"
		}
		dispositionArgs := map[string]string{}
		if filename := r.PathValue("filename"); filename != "" {
			dispositionArgs["filename"] = filename
		}
		w.Header().Set("Content-Type", mimeType)
		w.Header().Set("Content-Disposition", mime.FormatMediaType(contentDisposition, dispositionArgs))
		// Note: this won't check the Close result like it should, but it's probably not a big deal here
		stream = encInfo.DecryptStream(stream)
	} else if filename := r.PathValue("filename"); filename != "" {
		contentDisposition, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
		if contentDisposition == "" {
			contentDisposition = "attachment"
		}
		w.Header().Set("Content-Disposition", mime.FormatMediaType(contentDisposition, map[string]string{
			"filename": filename,
		}))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, stream)
}

func (br *Connector) GetPublicMediaAddress(contentURI id.ContentURIString) string {
	return br.getPublicMediaAddressWithFileName(contentURI, "")
}

func (br *Connector) getPublicMediaAddressWithFileName(contentURI id.ContentURIString, fileName string) string {
	if br.pubMediaSigKey == nil {
		return ""
	}
	parsed, err := contentURI.Parse()
	if err != nil || !parsed.IsValid() {
		return ""
	}
	fileName = url.PathEscape(strings.ReplaceAll(fileName, "/", "_"))
	if fileName == ".." {
		fileName = ""
	}
	parts := []string{
		br.GetPublicAddress(),
		strings.Trim(br.Config.PublicMedia.PathPrefix, "/"),
		parsed.Homeserver,
		parsed.FileID,
		base64.RawURLEncoding.EncodeToString(br.makePublicMediaChecksum(parsed)),
		fileName,
	}
	if fileName == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, "/")
}

func (br *Connector) GetPublicMediaAddressForEvent(ctx context.Context, evt *event.MessageEventContent) (string, error) {
	if br.pubMediaSigKey == nil {
		return "", bridgev2.ErrPublicMediaDisabled
	}
	if !br.Config.PublicMedia.UseDatabase {
		if evt.File != nil {
			return "", fmt.Errorf("can't generate address for encrypted file: %w", bridgev2.ErrPublicMediaDatabaseDisabled)
		}
		return br.getPublicMediaAddressWithFileName(evt.URL, evt.GetFileName()), nil
	}
	mxc := evt.URL
	var keys *attachment.EncryptedFile
	if evt.File != nil {
		mxc = evt.File.URL
		keys = &evt.File.EncryptedFile
	}
	parsedMXC, err := mxc.Parse()
	if err != nil {
		return "", fmt.Errorf("%w: failed to parse MXC: %w", bridgev2.ErrPublicMediaGenerateFailed, err)
	}
	pm := &database.PublicMedia{
		MXC:      parsedMXC,
		Keys:     keys,
		MimeType: evt.GetInfo().MimeType,
	}
	if br.Config.PublicMedia.Expiry > 0 {
		pm.Expiry = time.Now().Add(time.Duration(br.Config.PublicMedia.Expiry) * time.Second)
	}
	pm.PublicID = base64.RawURLEncoding.EncodeToString(br.hashDBPublicMedia(pm))
	err = br.Bridge.DB.PublicMedia.Put(ctx, pm)
	if err != nil {
		return "", fmt.Errorf("%w: failed to store public media in database: %w", bridgev2.ErrPublicMediaGenerateFailed, err)
	}
	fileName := url.PathEscape(strings.ReplaceAll(evt.GetFileName(), "/", "_"))
	if fileName == ".." {
		fileName = ""
	}
	parts := []string{
		br.GetPublicAddress(),
		strings.Trim(br.Config.PublicMedia.PathPrefix, "/"),
		pm.PublicID,
		fileName,
	}
	if fileName == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, "/"), nil
}
