package utilities

import (
	"bytes"
	"testing"
)

func TestSHA256(t *testing.T) {
	plainText := []byte("Hello, World")
	expected := []byte("A2daxT/5zRU1zMffzfosRYxSGDcfQY3BNvLRmsH76KU")
	if !bytes.Equal(Sha256(plainText), expected) {
		t.Fatal("sha256 failed")
	}
}
