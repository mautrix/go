// Copyright (c) 2026 Nick Mills-Barrett
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"cmp"
	"context"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

type sensitiveQueryParamsKey struct{}

func WithSensitiveQueryParams(ctx context.Context, keys ...string) context.Context {
	previous, _ := ctx.Value(sensitiveQueryParamsKey{}).([]string)
	return context.WithValue(ctx, sensitiveQueryParamsKey{}, slices.Concat(previous, keys))
}

type ClientHTTPLogRedactor struct {
	url      string
	replacer *strings.Replacer
}

func NewClientHTTPLogRedactor(ctx context.Context, requestURL *url.URL) *ClientHTTPLogRedactor {
	keys, _ := ctx.Value(sensitiveQueryParamsKey{}).([]string)
	if len(keys) == 0 {
		return nil
	}
	parts := strings.Split(requestURL.RawQuery, "&")
	values := make(map[string]struct{})
	addValue := func(value string) {
		values[value] = struct{}{}
		quoted := strconv.Quote(value)
		values[quoted[1:len(quoted)-1]] = struct{}{}
	}
	for i, part := range parts {
		rawKey, rawValue, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil || !slices.Contains(keys, key) || rawValue == "" {
			continue
		}
		parts[i] = rawKey + "=[redacted]"
		addValue(rawValue)
		if value, err := url.QueryUnescape(rawValue); err == nil {
			addValue(value)
			addValue(url.QueryEscape(value))
			addValue(url.PathEscape(value))
		}
	}
	if len(values) == 0 {
		return nil
	}
	secrets := make([]string, 0, len(values))
	for value := range values {
		secrets = append(secrets, value)
	}
	slices.SortFunc(secrets, func(a, b string) int {
		return cmp.Compare(len(b), len(a))
	})
	replacements := make([]string, 0, len(secrets)*2)
	for _, value := range secrets {
		replacements = append(replacements, value, "[redacted]")
	}
	logURL := *requestURL
	logURL.RawQuery = strings.Join(parts, "&")
	return &ClientHTTPLogRedactor{
		url:      logURL.String(),
		replacer: strings.NewReplacer(replacements...),
	}
}

func (r *ClientHTTPLogRedactor) String() string {
	return r.url
}

func (r *ClientHTTPLogRedactor) Redact(message string) string {
	if r == nil {
		return message
	}
	return r.replacer.Replace(message)
}

func (r *ClientHTTPLogRedactor) RedactError(err error) error {
	if r == nil || err == nil {
		return err
	}
	message := err.Error()
	redacted := r.Redact(message)
	if message == redacted {
		return err
	}
	return &clientHTTPRedactedError{err, redacted}
}

type clientHTTPRedactedError struct {
	err     error
	message string
}

func (e *clientHTTPRedactedError) Error() string {
	return e.message
}

func (e *clientHTTPRedactedError) Unwrap() error {
	return e.err
}
