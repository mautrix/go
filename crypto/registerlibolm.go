//go:build libolm

package crypto

import "maunium.net/go/mautrix/crypto/libolm"

func init() {
	libolm.Register()
}
