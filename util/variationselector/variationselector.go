// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package variationselector provides utility functions for adding and removing emoji variation selectors (16)
// that matches the suggestions in the Matrix spec.
package variationselector

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:generate ./generate.sh
//go:embed emojis-with-variations.json
var emojisWithVariationsJSON []byte

var variationReplacer *strings.Replacer

// The variation replacer will add incorrect variation selectors before skin tones, this removes those.
var skinToneReplacer = strings.NewReplacer(
	"\ufe0f\U0001F3FB", "\U0001F3FB",
	"\ufe0f\U0001F3FC", "\U0001F3FC",
	"\ufe0f\U0001F3FD", "\U0001F3FD",
	"\ufe0f\U0001F3FE", "\U0001F3FE",
	"\ufe0f\U0001F3FF", "\U0001F3FF",
)

func init() {
	var emojisWithVariations []string
	err := json.Unmarshal(emojisWithVariationsJSON, &emojisWithVariations)
	if err != nil {
		panic(err)
	}
	replaceInput := make([]string, 2*len(emojisWithVariations))
	for i, emoji := range emojisWithVariations {
		replaceInput[i*2] = emoji
		replaceInput[(i*2)+1] = emoji + VS16
	}
	variationReplacer = strings.NewReplacer(replaceInput...)
}

const VS16 = "\ufe0f"

// Add adds emoji variation selectors to all emojis that have multiple forms in the given string.
//
// This will remove all variation selectors first to make sure it doesn't add duplicates.
func Add(val string) string {
	return skinToneReplacer.Replace(variationReplacer.Replace(Remove(val)))
}

// Remove removes all emoji variation selectors in the given string.
func Remove(val string) string {
	return strings.ReplaceAll(val, VS16, "")
}
