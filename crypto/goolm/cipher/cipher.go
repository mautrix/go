// Package cipher provides the methods and structs to do encryptions for
// olm/megolm.
package cipher

// Cipher defines a valid cipher.
type Cipher interface {
	// Encrypt encrypts the plaintext.
	Encrypt(key, plaintext []byte) (ciphertext []byte, err error)

	// Decrypt decrypts the ciphertext.
	Decrypt(key, ciphertext []byte) (plaintext []byte, err error)

	//MAC returns the MAC of the message calculated with the key.
	MAC(key, message []byte) ([]byte, error)

	//Verify checks the MAC of the message calculated with the key against the givenMAC.
	Verify(key, message, givenMAC []byte) (bool, error)
}
