package session_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/megolm"
	"maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/olm"
)

func TestOutboundPickleJSON(t *testing.T) {
	pickleKey := []byte("secretKey")
	sess, err := session.NewMegolmOutboundSession()
	assert.NoError(t, err)
	kp, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	sess.SigningKey = kp
	pickled, err := sess.PickleAsJSON(pickleKey)
	assert.NoError(t, err)

	newSession := session.MegolmOutboundSession{}
	err = newSession.UnpickleAsJSON(pickled, pickleKey)
	assert.NoError(t, err)
	assert.Equal(t, sess.ID(), newSession.ID())
	assert.Equal(t, sess.SigningKey, newSession.SigningKey)
	assert.Equal(t, sess.Ratchet, newSession.Ratchet)
}

func TestInboundPickleJSON(t *testing.T) {
	pickleKey := []byte("secretKey")
	sess := session.MegolmInboundSession{}
	kp, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	sess.SigningKey = kp.PublicKey
	var randomData [megolm.RatchetParts * megolm.RatchetPartLength]byte
	_, err = rand.Read(randomData[:])
	assert.NoError(t, err)
	ratchet, err := megolm.New(0, randomData)
	assert.NoError(t, err)
	sess.Ratchet = *ratchet
	pickled, err := sess.PickleAsJSON(pickleKey)
	assert.NoError(t, err)

	newSession := session.MegolmInboundSession{}
	err = newSession.UnpickleAsJSON(pickled, pickleKey)
	assert.NoError(t, err)
	assert.Equal(t, sess.ID(), newSession.ID())
	assert.Equal(t, sess.SigningKey, newSession.SigningKey)
	assert.Equal(t, sess.Ratchet, newSession.Ratchet)
}

func TestGroupSendReceive(t *testing.T) {
	randomData := []byte(
		"0123456789ABDEF0123456789ABCDEF" +
			"0123456789ABDEF0123456789ABCDEF" +
			"0123456789ABDEF0123456789ABCDEF" +
			"0123456789ABDEF0123456789ABCDEF" +
			"0123456789ABDEF0123456789ABCDEF" +
			"0123456789ABDEF0123456789ABCDEF",
	)

	outboundSession, err := session.NewMegolmOutboundSession()
	assert.NoError(t, err)
	copy(outboundSession.Ratchet.Data[:], randomData)
	assert.EqualValues(t, 0, outboundSession.Ratchet.Counter)

	sessionSharing, err := outboundSession.SessionSharingMessage()
	assert.NoError(t, err)
	plainText := []byte("Message")
	ciphertext, err := outboundSession.Encrypt(plainText)
	assert.NoError(t, err)
	assert.EqualValues(t, 1, outboundSession.Ratchet.Counter)

	//build inbound session
	inboundSession, err := session.NewMegolmInboundSession(sessionSharing)
	assert.NoError(t, err)
	assert.True(t, inboundSession.SigningKeyVerified)
	assert.Equal(t, outboundSession.ID(), inboundSession.ID())

	//decode message
	decoded, _, err := inboundSession.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decoded)
}

func TestGroupSessionExportImport(t *testing.T) {
	plaintext := []byte("Message")
	sessionKey := []byte(
		"AgAAAAAwMTIzNDU2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc4OUFCREVGM" +
			"DEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkRFRjAxMjM0NTY3ODlBQkNERUYwMTIzND" +
			"U2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMw0bdg1BDq4Px/slBow06q8n/B9WBfw" +
			"WYyNOB8DlUmXGGwrFmaSb9bR/eY8xgERrxmP07hFmD9uqA2p8PMHdnV5ysmgufE6oLZ5+" +
			"8/mWQOW3VVTnDIlnwd8oHUYRuk8TCQ",
	)
	message := []byte(
		"AwgAEhAcbh6UpbByoyZxufQ+h2B+8XHMjhR69G8F4+qjMaFlnIXusJZX3r8LnRORG9T3D" +
			"XFdbVuvIWrLyRfm4i8QRbe8VPwGRFG57B1CtmxanuP8bHtnnYqlwPsD",
	)

	//init inbound
	inboundSession, err := session.NewMegolmInboundSession(sessionKey)
	assert.NoError(t, err)
	assert.True(t, inboundSession.SigningKeyVerified)

	decrypted, _, err := inboundSession.Decrypt(message)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	//Export the keys
	exported, err := inboundSession.Export(0)
	assert.NoError(t, err)

	secondInboundSession, err := session.NewMegolmInboundSessionFromExport(exported)
	assert.NoError(t, err)
	assert.False(t, secondInboundSession.SigningKeyVerified)

	//decrypt with new session
	decrypted, _, err = secondInboundSession.Decrypt(message)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	assert.True(t, secondInboundSession.SigningKeyVerified)
}

func TestBadSignatureGroupMessage(t *testing.T) {
	plaintext := []byte("Message")
	sessionKey := []byte(
		"AgAAAAAwMTIzNDU2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc4OUFCREVGM" +
			"DEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkRFRjAxMjM0NTY3ODlBQkNERUYwMTIzND" +
			"U2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMztqJ7zOtqQtYqOo0CpvDXNlMhV3HeJ" +
			"DpjrASKGLWdop4lx1cSN3Xv1TgfLPW8rhGiW+hHiMxd36nRuxscNv9k4oJA/KP+o0mi1w" +
			"v44StrEJ1wwx9WZHBUIWkQbaBSuBDw",
	)
	message := []byte(
		"AwgAEhAcbh6UpbByoyZxufQ+h2B+8XHMjhR69G8nP4pNZGl/3QMgrzCZPmP+F2aPLyKPz" +
			"xRPBMUkeXRJ6Iqm5NeOdx2eERgTW7P20CM+lL3Xpk+ZUOOPvsSQNaAL",
	)

	//init inbound
	inboundSession, err := session.NewMegolmInboundSession(sessionKey)
	assert.NoError(t, err)
	assert.True(t, inboundSession.SigningKeyVerified)

	decrypted, _, err := inboundSession.Decrypt(message)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	//Now twiddle the signature
	copy(message[len(message)-1:], []byte("E"))
	_, _, err = inboundSession.Decrypt(message)
	assert.ErrorIs(t, err, olm.ErrBadSignature)
}

func TestOutbountPickle(t *testing.T) {
	pickledDataFromLibOlm := []byte("icDKYm0b4aO23WgUuOxdpPoxC0UlEOYPVeuduNH3IkpFsmnWx5KuEOpxGiZw5IuB/sSn2RZUCTiJ90IvgC7AClkYGHep9O8lpiqQX73XVKD9okZDCAkBc83eEq0DKYC7HBkGRAU/4T6QPIBBY3UK4QZwULLE/fLsi3j4YZBehMtnlsqgHK0q1bvX4cRznZItUO3TiOp5I+6PnQka6n8eHTyIEh3tCetilD+BKnHvtakE0eHHvG6pjEsMNN/vs7lkB5rV6XkoUKHLTE1dAfFunYEeHEZuKQpbG385dBwaMJXt4JrC0hU5jnv6jWNqAA0Ud9GxRDvkp04")
	pickleKey := []byte("secret_key")
	sess, err := session.MegolmOutboundSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	assert.NoError(t, err)
	newPickled, err := sess.Pickle(pickleKey)
	assert.NoError(t, err)
	assert.Equal(t, pickledDataFromLibOlm, newPickled)

	pickledDataFromLibOlm = append(pickledDataFromLibOlm, []byte("a")...)
	_, err = session.MegolmOutboundSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	assert.ErrorIs(t, err, olm.ErrBadMAC)
}

func TestInbountPickle(t *testing.T) {
	pickledDataFromLibOlm := []byte("1/IPCdtUoQxMba5XT7sjjUW0Hrs7no9duGFnhsEmxzFX2H3qtRc4eaFBRZYXxOBRTGZ6eMgy3IiSrgAQ1gUlSZf5Q4AVKeBkhvN4LZ6hdhQFv91mM+C2C55/4B9/gDjJEbDGiRgLoMqbWPDV+y0F4h0KaR1V1PiTCC7zCi4WdxJQ098nJLgDL4VSsDbnaLcSMO60FOYgRN4KsLaKUGkXiiUBWp4boFMCiuTTOiyH8XlH0e9uWc0vMLyGNUcO8kCbpAnx3v1JTIVan3WGsnGv4K8Qu4M8GAkZewpexrsb2BSNNeLclOV9/cR203Y5KlzXcpiWNXSs8XoB3TLEtHYMnjuakMQfyrcXKIQntg4xPD/+wvfqkcMg9i7pcplQh7X2OK5ylrMZQrZkJ1fAYBGbBz1tykWOjfrZ")
	pickleKey := []byte("secret_key")
	sess, err := session.MegolmInboundSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	assert.NoError(t, err)
	newPickled, err := sess.Pickle(pickleKey)
	assert.NoError(t, err)
	assert.Equal(t, pickledDataFromLibOlm, newPickled)

	pickledDataFromLibOlm = append(pickledDataFromLibOlm, []byte("a")...)
	_, err = session.MegolmInboundSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	assert.ErrorIs(t, err, base64.CorruptInputError(416))
}
