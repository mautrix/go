// Copyright (c) 2022 Tulir Asokan
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
	assert.Equal(t, "\U0001f44d\U0001F3FD", variationselector.Add("\U0001f44d\U0001F3FD"))
	assert.Equal(t, "\U0001f44d\ufe0f", variationselector.Add("\U0001f44d"))
	assert.Equal(t, "\U0001f44d\ufe0f", variationselector.Add("\U0001f44d\ufe0f"))
	assert.Equal(t, "4\ufe0f\u20e3", variationselector.Add("4\u20e3"))
	assert.Equal(t, "4\ufe0f\u20e3", variationselector.Add("4\ufe0f\u20e3"))
	assert.Equal(t, "\U0001f914", variationselector.Add("\U0001f914"))
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
	fmt.Println(strconv.QuoteToASCII(variationselector.Add("\U0001f44d\U0001F3FD"))) // thumbs up with skin tone (shouldn't get selector)
	fmt.Println(strconv.QuoteToASCII(variationselector.Add("\U0001f914")))           // thinking face (shouldn't get selector)
	// Output:
	// "\U0001f44d\ufe0f"
	// "\U0001f44d\ufe0f"
	// "\U0001f44d\U0001f3fd"
	// "\U0001f914"
}

func ExampleRemove() {
	fmt.Println(strconv.QuoteToASCII(variationselector.Remove("\U0001f44d")))
	fmt.Println(strconv.QuoteToASCII(variationselector.Remove("\U0001f44d\ufe0f")))
	// Output:
	// "\U0001f44d"
	// "\U0001f44d"
}
