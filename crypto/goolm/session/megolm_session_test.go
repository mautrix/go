package session_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/megolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/session"
)

func TestOutboundPickleJSON(t *testing.T) {
	pickleKey := []byte("secretKey")
	sess, err := session.NewMegolmOutboundSession()
	if err != nil {
		t.Fatal(err)
	}
	kp, err := crypto.Ed25519GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sess.SigningKey = kp
	pickled, err := sess.PickleAsJSON(pickleKey)
	if err != nil {
		t.Fatal(err)
	}

	newSession := session.MegolmOutboundSession{}
	err = newSession.UnpickleAsJSON(pickled, pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	if sess.SessionID() != newSession.SessionID() {
		t.Fatal("session ids not equal")
	}
	if !bytes.Equal(sess.SigningKey.PrivateKey, newSession.SigningKey.PrivateKey) {
		t.Fatal("private keys not equal")
	}
	if !bytes.Equal(sess.Ratchet.Data[:], newSession.Ratchet.Data[:]) {
		t.Fatal("ratchet data not equal")
	}
	if sess.Ratchet.Counter != newSession.Ratchet.Counter {
		t.Fatal("ratchet counter not equal")
	}
}

func TestInboundPickleJSON(t *testing.T) {
	pickleKey := []byte("secretKey")
	sess := session.MegolmInboundSession{}
	kp, err := crypto.Ed25519GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sess.SigningKey = kp.PublicKey
	var randomData [megolm.RatchetParts * megolm.RatchetPartLength]byte
	_, err = rand.Read(randomData[:])
	if err != nil {
		t.Fatal(err)
	}
	ratchet, err := megolm.New(0, randomData)
	if err != nil {
		t.Fatal(err)
	}
	sess.Ratchet = *ratchet
	pickled, err := sess.PickleAsJSON(pickleKey)
	if err != nil {
		t.Fatal(err)
	}

	newSession := session.MegolmInboundSession{}
	err = newSession.UnpickleAsJSON(pickled, pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	if sess.SessionID() != newSession.SessionID() {
		t.Fatal("sess ids not equal")
	}
	if !bytes.Equal(sess.SigningKey, newSession.SigningKey) {
		t.Fatal("private keys not equal")
	}
	if !bytes.Equal(sess.Ratchet.Data[:], newSession.Ratchet.Data[:]) {
		t.Fatal("ratchet data not equal")
	}
	if sess.Ratchet.Counter != newSession.Ratchet.Counter {
		t.Fatal("ratchet counter not equal")
	}
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
	if err != nil {
		t.Fatal(err)
	}
	copy(outboundSession.Ratchet.Data[:], randomData)
	if outboundSession.Ratchet.Counter != 0 {
		t.Fatal("ratchet counter is not correkt")
	}
	sessionSharing, err := outboundSession.SessionSharingMessage()
	if err != nil {
		t.Fatal(err)
	}
	plainText := []byte("Message")
	ciphertext, err := outboundSession.Encrypt(plainText)
	if err != nil {
		t.Fatal(err)
	}
	if outboundSession.Ratchet.Counter != 1 {
		t.Fatal("ratchet counter is not correkt")
	}

	//build inbound session
	inboundSession, err := session.NewMegolmInboundSession(sessionSharing)
	if err != nil {
		t.Fatal(err)
	}
	if !inboundSession.SigningKeyVerified {
		t.Fatal("key not verified")
	}
	if inboundSession.SessionID() != outboundSession.SessionID() {
		t.Fatal("session ids not equal")
	}

	//decode message
	decoded, _, err := inboundSession.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plainText, decoded) {
		t.Fatal("messages not equal")
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if !inboundSession.SigningKeyVerified {
		t.Fatal("signing key not verified")
	}

	decrypted, _, err := inboundSession.Decrypt(message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("message is not correct")
	}

	//Export the keys
	exported, err := inboundSession.SessionExportMessage(0)
	if err != nil {
		t.Fatal(err)
	}

	secondInboundSession, err := session.NewMegolmInboundSessionFromExport(exported)
	if err != nil {
		t.Fatal(err)
	}
	if secondInboundSession.SigningKeyVerified {
		t.Fatal("signing key is verified")
	}
	//decrypt with new session
	decrypted, _, err = secondInboundSession.Decrypt(message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("message is not correct")
	}
	if !secondInboundSession.SigningKeyVerified {
		t.Fatal("signing key not verified")
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if !inboundSession.SigningKeyVerified {
		t.Fatal("signing key not verified")
	}

	decrypted, _, err := inboundSession.Decrypt(message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("message is not correct")
	}

	//Now twiddle the signature
	copy(message[len(message)-1:], []byte("E"))
	_, _, err = inboundSession.Decrypt(message)
	if err == nil {
		t.Fatal("Signature was changed but did not cause an error")
	}
	if !errors.Is(err, goolm.ErrBadSignature) {
		t.Fatalf("wrong error %s", err.Error())
	}
}

func TestOutbountPickle(t *testing.T) {
	pickledDataFromLibOlm := []byte("icDKYm0b4aO23WgUuOxdpPoxC0UlEOYPVeuduNH3IkpFsmnWx5KuEOpxGiZw5IuB/sSn2RZUCTiJ90IvgC7AClkYGHep9O8lpiqQX73XVKD9okZDCAkBc83eEq0DKYC7HBkGRAU/4T6QPIBBY3UK4QZwULLE/fLsi3j4YZBehMtnlsqgHK0q1bvX4cRznZItUO3TiOp5I+6PnQka6n8eHTyIEh3tCetilD+BKnHvtakE0eHHvG6pjEsMNN/vs7lkB5rV6XkoUKHLTE1dAfFunYEeHEZuKQpbG385dBwaMJXt4JrC0hU5jnv6jWNqAA0Ud9GxRDvkp04")
	pickleKey := []byte("secret_key")
	sess, err := session.MegolmOutboundSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	newPickled, err := sess.Pickle(pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pickledDataFromLibOlm, newPickled) {
		t.Fatal("pickled version does not equal libolm version")
	}
	pickledDataFromLibOlm = append(pickledDataFromLibOlm, []byte("a")...)
	_, err = session.MegolmOutboundSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	if err == nil {
		t.Fatal("should have gotten an error")
	}
}

func TestInbountPickle(t *testing.T) {
	pickledDataFromLibOlm := []byte("1/IPCdtUoQxMba5XT7sjjUW0Hrs7no9duGFnhsEmxzFX2H3qtRc4eaFBRZYXxOBRTGZ6eMgy3IiSrgAQ1gUlSZf5Q4AVKeBkhvN4LZ6hdhQFv91mM+C2C55/4B9/gDjJEbDGiRgLoMqbWPDV+y0F4h0KaR1V1PiTCC7zCi4WdxJQ098nJLgDL4VSsDbnaLcSMO60FOYgRN4KsLaKUGkXiiUBWp4boFMCiuTTOiyH8XlH0e9uWc0vMLyGNUcO8kCbpAnx3v1JTIVan3WGsnGv4K8Qu4M8GAkZewpexrsb2BSNNeLclOV9/cR203Y5KlzXcpiWNXSs8XoB3TLEtHYMnjuakMQfyrcXKIQntg4xPD/+wvfqkcMg9i7pcplQh7X2OK5ylrMZQrZkJ1fAYBGbBz1tykWOjfrZ")
	pickleKey := []byte("secret_key")
	sess, err := session.MegolmInboundSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	newPickled, err := sess.Pickle(pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pickledDataFromLibOlm, newPickled) {
		t.Fatal("pickled version does not equal libolm version")
	}
	pickledDataFromLibOlm = append(pickledDataFromLibOlm, []byte("a")...)
	_, err = session.MegolmInboundSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	if err == nil {
		t.Fatal("should have gotten an error")
	}
}
