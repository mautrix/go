package goolm

import (
	"encoding/base64"

	"github.com/pkg/errors"
)

// Base64Decode decodes the input. Padding characters ('=') will be added if needed.
func Base64Decode(input []byte) ([]byte, error) {
	//pad the input to multiple of 4
	addedPadding := 0
	for len(input)%4 != 0 {
		input = append(input, []byte("=")...)
		addedPadding++
	}
	if addedPadding >= 3 {
		return nil, errors.Wrap(ErrBase64InvalidLength, "")
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(input)))
	writtenBytes, err := base64.StdEncoding.Decode(decoded, input)
	if err != nil {
		return nil, errors.Wrap(ErrBadBase64, err.Error())
	}
	//DecodedLen returned the maximum size. However this might not be the true length.
	return decoded[:writtenBytes], nil
}

// Base64Encode encodes the input and strips all padding characters ('=') from the end.
func Base64Encode(input []byte) []byte {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(input)))
	base64.StdEncoding.Encode(encoded, input)
	//Remove padding = from output as libolm does so
	for curIndex := len(encoded) - 1; curIndex >= 0; curIndex-- {
		if string(encoded[curIndex]) != "=" {
			encoded = encoded[:curIndex+1]
			break
		}
	}
	return encoded
}
