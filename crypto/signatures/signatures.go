package signatures

import "maunium.net/go/mautrix/id"

// Signatures represents a set of signatures for some data from multiple users
// and keys.
type Signatures map[id.UserID]map[id.KeyID]string

// NewSingleSignature creates a new [Signatures] object with a single
// signature.
func NewSingleSignature(userID id.UserID, algorithm id.KeyAlgorithm, keyID string, signature string) Signatures {
	return Signatures{
		userID: {
			id.NewKeyID(algorithm, keyID): signature,
		},
	}
}
