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

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mediaproxy"
)

const MediaIDPrefix = "\U0001F408"
const MediaIDTruncatedHashLength = 16
const ContentURIMaxLength = 255

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

func (br *Connector) getDirectMedia(ctx context.Context, mediaIDStr string, params map[string]string) (response mediaproxy.GetMediaResponse, err error) {
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
	return br.Bridge.Network.(bridgev2.DirectMediableNetwork).Download(ctx, remoteMediaID, params)
}
