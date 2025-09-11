//go:build goolm

package crypto

import (
	"maunium.net/go/mautrix/crypto/goolm"
)

func init() {
	goolm.Register()
}
