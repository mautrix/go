package mautrix

import (
	"math/rand"
	"time"
)

const nonceAC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

var src = rand.NewSource(time.Now().UnixNano())

// GenerateNonce generates a random string
func GenerateNonce() string {
	b := make([]byte, 32)
	for i, cache, remain := len(b)-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(nonceAC) {
			b[i] = nonceAC[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
