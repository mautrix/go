// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package variationselector_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/util/variationselector"
)

func TestAdd(t *testing.T) {
	assert.Equal(t, "\U0001f44d\U0001f3fd", variationselector.Add("\U0001f44d\U0001f3fd"))
	assert.Equal(t, "\U0001f44d\ufe0f", variationselector.Add("\U0001f44d"))
	assert.Equal(t, "\U0001f44d\ufe0f", variationselector.Add("\U0001f44d\ufe0f"))
	assert.Equal(t, "4\ufe0f\u20e3", variationselector.Add("4\u20e3"))
	assert.Equal(t, "4\ufe0f\u20e3", variationselector.Add("4\ufe0f\u20e3"))
	assert.Equal(t, "\U0001f914", variationselector.Add("\U0001f914"))
}

func TestFullyQualify(t *testing.T) {
	assert.Equal(t, "\U0001f44d", variationselector.FullyQualify("\U0001f44d"))
	assert.Equal(t, "\U0001f44d", variationselector.FullyQualify("\U0001f44d\ufe0f"))
	assert.Equal(t, "4\ufe0f\u20e3", variationselector.FullyQualify("4\u20e3"))
	assert.Equal(t, "4\ufe0f\u20e3", variationselector.FullyQualify("4\ufe0f\u20e3"))
	assert.Equal(t, "\U0001f914", variationselector.FullyQualify("\U0001f914"))
	assert.Equal(t, "\u263a\ufe0f", variationselector.FullyQualify("\u263a"))
	assert.Equal(t, "\u263a\ufe0f", variationselector.FullyQualify("\u263a"))
	assert.Equal(t, "\U0001f3f3\ufe0f\u200D\U0001f308", variationselector.FullyQualify("\U0001f3f3\u200D\U0001f308"))
	assert.Equal(t, "\U0001f3f3\ufe0f\u200D\U0001f308", variationselector.FullyQualify("\U0001f3f3\ufe0f\u200D\U0001f308"))
}

func TestRemove(t *testing.T) {
	assert.Equal(t, "\U0001f44d", variationselector.Remove("\U0001f44d"))
	assert.Equal(t, "\U0001f44d", variationselector.Remove("\U0001f44d\ufe0f"))
	assert.Equal(t, "4\u20e3", variationselector.Remove("4\u20e3"))
	assert.Equal(t, "4\u20e3", variationselector.Remove("4\ufe0f\u20e3"))
	assert.Equal(t, "\U0001f914", variationselector.Remove("\U0001f914"))
}

func ExampleAdd() {
	fmt.Println(strconv.QuoteToASCII(variationselector.Add("\U0001f44d")))           // thumbs up (needs selector)
	fmt.Println(strconv.QuoteToASCII(variationselector.Add("\U0001f44d\ufe0f")))     // thumbs up with variation selector (stays as-is)
	fmt.Println(strconv.QuoteToASCII(variationselector.Add("\U0001f44d\U0001f3fd"))) // thumbs up with skin tone (shouldn't get selector)
	fmt.Println(strconv.QuoteToASCII(variationselector.Add("\U0001f914")))           // thinking face (shouldn't get selector)
	// Output:
	// "\U0001f44d\ufe0f"
	// "\U0001f44d\ufe0f"
	// "\U0001f44d\U0001f3fd"
	// "\U0001f914"
}

func ExampleFullyQualify() {
	fmt.Println(strconv.QuoteToASCII(variationselector.FullyQualify("\U0001f44d")))                       // thumbs up (already fully qualified)
	fmt.Println(strconv.QuoteToASCII(variationselector.FullyQualify("\U0001f44d\ufe0f")))                 // thumbs up with variation selector (variation selector removed)
	fmt.Println(strconv.QuoteToASCII(variationselector.FullyQualify("\U0001f44d\U0001f3fd")))             // thumbs up with skin tone (already fully qualified)
	fmt.Println(strconv.QuoteToASCII(variationselector.FullyQualify("\u263a")))                           // smiling face (unqualified, should get selector)
	fmt.Println(strconv.QuoteToASCII(variationselector.FullyQualify("\U0001f3f3\u200d\U0001f308")))       // rainbow flag (unqualified, should get selector)
	fmt.Println(strconv.QuoteToASCII(variationselector.FullyQualify("\U0001f3f3\ufe0f\u200d\U0001f308"))) // rainbow flag with variation selector (already fully qualified)
	// Output:
	// "\U0001f44d"
	// "\U0001f44d"
	// "\U0001f44d\U0001f3fd"
	// "\u263a\ufe0f"
	// "\U0001f3f3\ufe0f\u200d\U0001f308"
	// "\U0001f3f3\ufe0f\u200d\U0001f308"
}

func ExampleRemove() {
	fmt.Println(strconv.QuoteToASCII(variationselector.Remove("\U0001f44d")))
	fmt.Println(strconv.QuoteToASCII(variationselector.Remove("\U0001f44d\ufe0f")))
	// Output:
	// "\U0001f44d"
	// "\U0001f44d"
}
