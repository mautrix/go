// Copyright (c) 2023 Tulir Asokan
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

//go:embed fully-qualified-variations.json
var fullyQualifiedVariationsJSON []byte

var variationReplacer, fullyQualifier *strings.Replacer

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

	var fullyQualifiedVariations []string
	err = json.Unmarshal(fullyQualifiedVariationsJSON, &fullyQualifiedVariations)
	if err != nil {
		panic(err)
	}
	replaceInput = make([]string, 2*len(fullyQualifiedVariations))
	for i, emoji := range fullyQualifiedVariations {
		replaceInput[i*2] = strings.ReplaceAll(emoji, VS16, "")
		replaceInput[(i*2)+1] = emoji
	}
	fullyQualifier = strings.NewReplacer(replaceInput...)
}

const VS16 = "\ufe0f"

// Add adds emoji variation selectors to all emojis that have multiple forms in the given string.
//
// Variation selectors will be added to everything that is allowed to have both a text presentation and
// an emoji presentation according to Unicode Technical Standard #51.
// If you only want to add variation selectors necessary for fully-qualified forms, use FullyQualify instead.
//
// This method uses data from emoji-variation-sequences.txt in the official Unicode emoji data set.
//
// This will remove all variation selectors first to make sure it doesn't add duplicates.
func Add(val string) string {
	return skinToneReplacer.Replace(variationReplacer.Replace(Remove(val)))
}

// Remove removes all emoji variation selectors in the given string.
func Remove(val string) string {
	return strings.ReplaceAll(val, VS16, "")
}

// FullyQualify converts all emojis to their fully-qualified form by adding variation selectors where necessary.
//
// This will not add variation selectors to all possible emojis, only the ones that require a variation selector
// to be "fully qualified" according to Unicode Technical Standard #51.
// If you want to add variation selectors in all allowed cases, use Add instead.
//
// This method uses data from emoji-test.txt in the official Unicode emoji data set.
//
// N.B. This method is not currently used by the Matrix spec, but it is included as bridging to other networks may need it.
func FullyQualify(val string) string {
	return fullyQualifier.Replace(Remove(val))
}
