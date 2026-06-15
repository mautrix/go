// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mediaproxy"
)

const MediaIDPrefix = "\U0001F408"
const MediaIDTruncatedHashLength = 16
const ContentURIMaxLength = 255

// Direct media downloads can race with message persistence: bridgev2's
// sendConvertedMessage (portal.go) sends the Matrix event via intent.SendMessage
// *before* inserting the message row into the database (the row needs the MXID
// returned by the send, so the order can't be flipped). With a local bridge the
// Matrix client may auto-download the generated mxc:// URI within milliseconds of
// the send, before the connector has stored the message row. The connector's
// Download then can't find the message and returns an error, which the media proxy
// surfaces to the client as a terminal "not found" (the iOS "Something went wrong").
//
// To paper over that narrow race we retry the connector Download a bounded number
// of times. Connectors signal "message not found" inconsistently (e.g. the Meta
// connector returns a plain fmt.Errorf("message not found")), so there is no
// reliable typed/sentinel not-found error to scope the retry to at this layer.
// We therefore retry on any error; the cost is at most ~directMediaRetryMax *
// directMediaRetryDelay of added latency on the genuine-failure path, which is
// acceptable since these requests are already failing.
const (
	directMediaRetryMax   = 10
	directMediaRetryDelay = 200 * time.Millisecond
)

func (br *Connector) initDirectMedia() error {
	if !br.Config.DirectMedia.Enabled {
		return nil
	}
	dmn, ok := br.Bridge.Network.(bridgev2.DirectMediableNetwork)
	if !ok {
		return fmt.Errorf("direct media is enabled in config, but the network connector does not support it")
	}
	var err error
	br.MediaProxy, err = mediaproxy.NewFromConfig(br.Config.DirectMedia.BasicConfig, br.getDirectMedia)
	if err != nil {
		return fmt.Errorf("failed to initialize media proxy: %w", err)
	}
	br.MediaProxy.RegisterRoutes(br.AS.Router, br.Log.With().Str("component", "media proxy").Logger())
	br.dmaSigKey = sha256.Sum256(br.MediaProxy.GetServerKey().Priv.Seed())
	dmn.SetUseDirectMedia()
	br.Log.Debug().Str("server_name", br.MediaProxy.GetServerName()).Msg("Enabled direct media access")
	return nil
}

func (br *Connector) hashMediaID(data []byte) []byte {
	hasher := hmac.New(sha256.New, br.dmaSigKey[:])
	hasher.Write(data)
	return hasher.Sum(nil)[:MediaIDTruncatedHashLength]
}

func (br *Connector) GenerateContentURI(ctx context.Context, mediaID networkid.MediaID) (id.ContentURIString, error) {
	if br.MediaProxy == nil {
		return "", bridgev2.ErrDirectMediaNotEnabled
	}
	buf := make([]byte, len(MediaIDPrefix)+len(mediaID)+MediaIDTruncatedHashLength)
	copy(buf, MediaIDPrefix)
	copy(buf[len(MediaIDPrefix):], mediaID)
	truncatedHash := br.hashMediaID(buf[:len(MediaIDPrefix)+len(mediaID)])
	copy(buf[len(MediaIDPrefix)+len(mediaID):], truncatedHash)
	mxc := id.ContentURI{
		Homeserver: br.MediaProxy.GetServerName(),
		FileID:     br.Config.DirectMedia.MediaIDPrefix + base64.RawURLEncoding.EncodeToString(buf),
	}.CUString()
	if len(mxc) > ContentURIMaxLength {
		return "", fmt.Errorf("content URI too long (%d > %d)", len(mxc), ContentURIMaxLength)
	}
	return mxc, nil
}

func (br *Connector) ParseContentURI(ctx context.Context, mxc id.ContentURIString) (networkid.MediaID, error) {
	if br.MediaProxy == nil {
		return nil, bridgev2.ErrDirectMediaNotEnabled
	}
	parsed, err := mxc.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse mxc URI: %w", err)
	} else if parsed.Homeserver != br.MediaProxy.GetServerName() {
		return nil, fmt.Errorf("mxc URI homeserver does not match media proxy server name")
	}
	return br.parseMediaID(parsed.FileID)
}

func (br *Connector) parseMediaID(mediaIDStr string) (networkid.MediaID, error) {
	mediaID, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(mediaIDStr, br.Config.DirectMedia.MediaIDPrefix))
	if err != nil || !bytes.HasPrefix(mediaID, []byte(MediaIDPrefix)) || len(mediaID) < len(MediaIDPrefix)+MediaIDTruncatedHashLength+1 {
		return nil, mediaproxy.ErrInvalidMediaIDSyntax
	}
	receivedHash := mediaID[len(mediaID)-MediaIDTruncatedHashLength:]
	expectedHash := br.hashMediaID(mediaID[:len(mediaID)-MediaIDTruncatedHashLength])
	if !hmac.Equal(receivedHash, expectedHash) {
		return nil, mautrix.MNotFound.WithMessage("Invalid checksum in media ID part")
	}
	remoteMediaID := networkid.MediaID(mediaID[len(MediaIDPrefix) : len(mediaID)-MediaIDTruncatedHashLength])
	return remoteMediaID, nil
}

func (br *Connector) getDirectMedia(ctx context.Context, mediaIDStr string, params map[string]string) (response mediaproxy.GetMediaResponse, err error) {
	remoteMediaID, err := br.parseMediaID(mediaIDStr)
	if err != nil {
		return response, err
	}
	dmn := br.Bridge.Network.(bridgev2.DirectMediableNetwork)
	// Retry the download briefly to work around the send-before-insert race in
	// bridgev2's sendConvertedMessage (see the directMediaRetry* doc comment above).
	for attempt := 0; ; attempt++ {
		response, err = dmn.Download(ctx, remoteMediaID, params)
		if err == nil || attempt >= directMediaRetryMax {
			return response, err
		}
		zerolog.Ctx(ctx).Debug().Err(err).
			Int("attempt", attempt+1).
			Int("max_attempts", directMediaRetryMax+1).
			Msg("Direct media download failed, retrying in case message is not yet persisted")
		select {
		case <-time.After(directMediaRetryDelay):
		case <-ctx.Done():
			return response, ctx.Err()
		}
	}
}
