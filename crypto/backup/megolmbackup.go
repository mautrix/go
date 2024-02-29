package backup

import (
	"github.com/element-hq/mautrix-go/crypto/signatures"
	"github.com/element-hq/mautrix-go/id"
)

// MegolmAuthData is the auth_data when the key backup is created with
// the [id.KeyBackupAlgorithmMegolmBackupV1] algorithm as defined in
// [Section 11.12.3.2.2 of the Spec].
//
// [Section 11.12.3.2.2 of the Spec]: https://spec.matrix.org/v1.9/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2
type MegolmAuthData struct {
	PublicKey  id.Ed25519            `json:"public_key"`
	Signatures signatures.Signatures `json:"signatures"`
}

type SenderClaimedKeys struct {
	Ed25519 id.Ed25519 `json:"ed25519"`
}

// MegolmSessionData is the decrypted session_data when the key backup is created
// with the [id.KeyBackupAlgorithmMegolmBackupV1] algorithm as defined in
// [Section 11.12.3.2.2 of the Spec].
//
// [Section 11.12.3.2.2 of the Spec]: https://spec.matrix.org/v1.9/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2
type MegolmSessionData struct {
	Algorithm          id.Algorithm      `json:"algorithm"`
	ForwardingKeyChain []string          `json:"forwarding_curve25519_key_chain"`
	SenderClaimedKeys  SenderClaimedKeys `json:"sender_claimed_keys"`
	SenderKey          id.SenderKey      `json:"sender_key"`
	SessionKey         []byte            `json:"session_key"`
}
