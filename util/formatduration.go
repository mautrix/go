// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package util

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var Day = 24 * time.Hour
var Week = 7 * Day

func pluralize(value int, unit string) string {
	if value == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", value, unit)
}

func appendDurationPart(time, unit time.Duration, name string, parts *[]string) (remainder time.Duration) {
	if time < unit {
		return time
	}
	value := int(time / unit)
	remainder = time % unit
	*parts = append(*parts, pluralize(value, name))
	return
}

func FormatDuration(d time.Duration) string {
	if d < 0 {
		panic(errors.New("FormatDuration: negative duration"))
	} else if d < time.Second {
		return "now"
	}
	parts := make([]string, 0, 2)
	d = appendDurationPart(d, Week, "week", &parts)
	d = appendDurationPart(d, Day, "day", &parts)
	d = appendDurationPart(d, time.Hour, "hour", &parts)
	d = appendDurationPart(d, time.Minute, "minute", &parts)
	d = appendDurationPart(d, time.Second, "second", &parts)
	if len(parts) > 2 {
		parts[0] = strings.Join(parts[:len(parts)-1], ", ")
		parts[1] = parts[len(parts)-1]
		parts = parts[:2]
	}
	return strings.Join(parts, " and ")
}
