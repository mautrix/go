// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"time"
)

type TimeMixin struct {
	CreationTime time.Time
	UseTime      time.Time
}

type ExpirationMixin struct {
	TimeMixin
	MaxAge time.Duration
}

func (exp *ExpirationMixin) Expired() bool {
	return exp.CreationTime.Add(exp.MaxAge).Before(time.Now())
}
