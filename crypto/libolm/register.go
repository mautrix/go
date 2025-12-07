package libolm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"
import (
	"unsafe"

	"maunium.net/go/mautrix/crypto/olm"
)

var pickleKey = []byte("maunium.net/go/mautrix/crypto/olm")

func Register() {
	olm.Driver = "libolm"

	olm.GetVersion = func() (major, minor, patch uint8) {
		C.olm_get_library_version(
			(*C.uint8_t)(unsafe.Pointer(&major)),
			(*C.uint8_t)(unsafe.Pointer(&minor)),
			(*C.uint8_t)(unsafe.Pointer(&patch)))
		return 3, 2, 15
	}
	olm.SetPickleKeyImpl = func(key []byte) {
		pickleKey = key
	}

	olm.InitNewAccount = func() (olm.Account, error) {
		return NewAccount()
	}
	olm.InitBlankAccount = func() olm.Account {
		return NewBlankAccount()
	}
	olm.InitNewAccountFromPickled = func(pickled, key []byte) (olm.Account, error) {
		return AccountFromPickled(pickled, key)
	}

	olm.InitSessionFromPickled = func(pickled, key []byte) (olm.Session, error) {
		return SessionFromPickled(pickled, key)
	}
	olm.InitNewBlankSession = func() olm.Session {
		return NewBlankSession()
	}

	olm.InitNewPKSigning = func() (olm.PKSigning, error) { return NewPKSigning() }
	olm.InitNewPKSigningFromSeed = func(seed []byte) (olm.PKSigning, error) {
		return NewPKSigningFromSeed(seed)
	}
	olm.InitNewPKDecryptionFromPrivateKey = func(privateKey []byte) (olm.PKDecryption, error) {
		return NewPkDecryption(privateKey)
	}

	olm.InitInboundGroupSessionFromPickled = func(pickled, key []byte) (olm.InboundGroupSession, error) {
		return InboundGroupSessionFromPickled(pickled, key)
	}
	olm.InitNewInboundGroupSession = func(sessionKey []byte) (olm.InboundGroupSession, error) {
		return NewInboundGroupSession(sessionKey)
	}
	olm.InitInboundGroupSessionImport = func(sessionKey []byte) (olm.InboundGroupSession, error) {
		return InboundGroupSessionImport(sessionKey)
	}
	olm.InitBlankInboundGroupSession = func() olm.InboundGroupSession {
		return NewBlankInboundGroupSession()
	}

	olm.InitNewOutboundGroupSessionFromPickled = func(pickled, key []byte) (olm.OutboundGroupSession, error) {
		if len(pickled) == 0 {
			return nil, olm.ErrEmptyInput
		}
		s := NewBlankOutboundGroupSession()
		return s, s.Unpickle(pickled, key)
	}
	olm.InitNewOutboundGroupSession = func() (olm.OutboundGroupSession, error) { return NewOutboundGroupSession() }
	olm.InitNewBlankOutboundGroupSession = func() olm.OutboundGroupSession { return NewBlankOutboundGroupSession() }
}
