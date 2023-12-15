package goolm

import (
	"bytes"
	"errors"
	"testing"
)

func TestBase64Encode(t *testing.T) {
	input := []byte("Hello World")
	expected := []byte("SGVsbG8gV29ybGQ")
	result := Base64Encode(input)
	if !bytes.Equal(result, expected) {
		t.Fatalf("expected '%s' but got '%s'", string(expected), string(result))
	}
}

func TestBase64Decode(t *testing.T) {
	input := []byte("SGVsbG8gV29ybGQ")
	expected := []byte("Hello World")
	result, err := Base64Decode(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, expected) {
		t.Fatalf("expected '%s' but got '%s'", string(expected), string(result))
	}
	//This should fai
	_, err = Base64Decode([]byte("SGVsbG8gV29ybGQab"))
	if err == nil {
		t.Fatal("decoded wrong input")
	}
	if !errors.Is(err, ErrBase64InvalidLength) {
		t.Fatalf("got other error as expected: %s", err)
	}
}

func TestBase64DecodeFail(t *testing.T) {
	input := []byte("SGVsbG8gV29ybGQab")
	_, err := Base64Decode(input)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrBase64InvalidLength) {
		t.Fatal(err)
	}
}
