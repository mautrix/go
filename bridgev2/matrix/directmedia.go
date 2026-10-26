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
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mediaproxy"
)

const MediaIDPrefix = "\U0001F408"
const EncryptedMediaIDPrefix = "\U0001F63C"
const MediaIDTruncatedHashLength = 16
const EncryptedMediaIDRandomPartLength = 8
const ContentURIMaxLength = 255

func init() {
	if len(MediaIDPrefix) != len(EncryptedMediaIDPrefix) {
		panic("MediaIDPrefix and EncryptedMediaIDPrefix must be the same length")
	}
}

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
	return br.generateContentURIInternal(mediaID, false)
}

func (br *Connector) generateContentURIInternal(mediaID networkid.MediaID, encrypted bool) (id.ContentURIString, error) {
	if br.MediaProxy == nil {
		return "", bridgev2.ErrDirectMediaNotEnabled
	}
	prefixLen := len(MediaIDPrefix)
	if encrypted {
		prefixLen = len(EncryptedMediaIDPrefix) + EncryptedMediaIDRandomPartLength
	}
	buf := make([]byte, prefixLen+len(mediaID)+MediaIDTruncatedHashLength)
	if encrypted {
		copy(buf, EncryptedMediaIDPrefix)
		binary.BigEndian.PutUint64(buf[len(EncryptedMediaIDPrefix):len(EncryptedMediaIDPrefix)+EncryptedMediaIDRandomPartLength], rand.Uint64())
	} else {
		copy(buf, MediaIDPrefix)
	}
	copy(buf[prefixLen:], mediaID)
	truncatedHash := br.hashMediaID(buf[:prefixLen+len(mediaID)])
	copy(buf[prefixLen+len(mediaID):], truncatedHash)
	mxc := id.ContentURI{
		Homeserver: br.MediaProxy.GetServerName(),
		FileID:     br.Config.DirectMedia.MediaIDPrefix + base64.RawURLEncoding.EncodeToString(buf),
	}.CUString()
	if len(mxc) > ContentURIMaxLength {
		return "", fmt.Errorf("content URI too long (%d > %d)", len(mxc), ContentURIMaxLength)
	}
	return mxc, nil
}

func (br *Connector) GenerateContentURIWithCrypto(ctx context.Context, roomID id.RoomID, mediaID networkid.MediaID) (id.ContentURIString, *event.EncryptedFileInfo, error) {
	if roomID != "" && br.Config.DirectMedia.Encrypted {
		if encrypted, err := br.isEncrypted(ctx, roomID); err != nil {
			return "", nil, fmt.Errorf("failed to check if room is encrypted: %w", err)
		} else if encrypted {
			mxc, err := br.generateContentURIInternal(mediaID, true)
			if err != nil {
				return "", nil, err
			}
			floeFile := attachment.NewFLOEFile()
			err = br.Bridge.DB.EncryptedDirectMedia.Put(ctx, &database.EncryptedDirectMedia{
				MediaID:    exerrors.Must(mxc.Parse()).FileID,
				FLOEKey:    floeFile.FLOEKey,
				FLOEHeader: floeFile.FLOEHeader,
			})
			if err != nil {
				return "", nil, fmt.Errorf("failed to store encryption info for media ID: %w", err)
			}
			return "", &event.EncryptedFileInfo{
				EncryptedFile: *floeFile.ToStandard(),
				URL:           mxc,
			}, nil
		}
	}
	mxc, err := br.generateContentURIInternal(mediaID, false)
	return mxc, nil, err
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
	mediaID, _, err := br.parseMediaID(parsed.FileID)
	return mediaID, err
}

func (br *Connector) parseMediaID(mediaIDStr string) (networkid.MediaID, bool, error) {
	mediaID, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(mediaIDStr, br.Config.DirectMedia.MediaIDPrefix))
	var encrypted bool
	minLength := len(MediaIDPrefix) + MediaIDTruncatedHashLength + 1
	if err != nil || len(mediaID) < minLength {
		return nil, false, mediaproxy.ErrInvalidMediaIDSyntax
	}
	receivedHash := mediaID[len(mediaID)-MediaIDTruncatedHashLength:]
	expectedHash := br.hashMediaID(mediaID[:len(mediaID)-MediaIDTruncatedHashLength])
	if !hmac.Equal(receivedHash, expectedHash) {
		return nil, false, mautrix.MNotFound.WithMessage("Invalid checksum in media ID part")
	}
	extraPrefixLength := 0
	if bytes.HasPrefix(mediaID, []byte(EncryptedMediaIDPrefix)) {
		encrypted = true
		extraPrefixLength = EncryptedMediaIDRandomPartLength
	} else if !bytes.HasPrefix(mediaID, []byte(MediaIDPrefix)) {
		return nil, false, mediaproxy.ErrInvalidMediaIDSyntax
	}
	minLength += extraPrefixLength
	if len(mediaID) < minLength {
		return nil, false, mediaproxy.ErrInvalidMediaIDSyntax
	}
	remoteMediaID := networkid.MediaID(mediaID[len(MediaIDPrefix)+extraPrefixLength : len(mediaID)-MediaIDTruncatedHashLength])
	return remoteMediaID, encrypted, nil
}

func (br *Connector) getDirectMedia(ctx context.Context, mediaIDStr string, params map[string]string) (response mediaproxy.GetMediaResponse, err error) {
	remoteMediaID, encrypted, err := br.parseMediaID(mediaIDStr)
	if err != nil {
		return response, err
	}
	var crypto *attachment.EncryptedFile
	if encrypted {
		meta, err := br.Bridge.DB.EncryptedDirectMedia.Get(ctx, mediaIDStr)
		if err != nil {
			return nil, fmt.Errorf("failed to get encryption info for media ID: %w", err)
		} else if meta == nil {
			return nil, fmt.Errorf("no encryption info found for media ID")
		} else if meta.FLOEKey == "" {
			zerolog.Ctx(ctx).Debug().
				Time("handled_at", meta.HandledAt).
				Msg("Got query for encrypted direct media that was already handled")
			return nil, fmt.Errorf("no key found for encrypted media ID")
		}
		crypto = (&attachment.FLOEFile{
			Version:    attachment.VersionBeeperFLOE,
			FLOEKey:    meta.FLOEKey,
			FLOEHeader: meta.FLOEHeader,
		}).ToStandard()
	}
	resp, err := br.Bridge.Network.(bridgev2.DirectMediableNetwork).Download(ctx, remoteMediaID, params)
	if err != nil {
		return nil, err
	}
	if crypto != nil {
		encryptable, ok := resp.(mediaproxy.GetMediaResponseEncryptable)
		if !ok {
			return nil, fmt.Errorf("media response is not encryptable")
		}
		return encryptable.WithEncryption(crypto), nil
	}
	return resp, nil
}
