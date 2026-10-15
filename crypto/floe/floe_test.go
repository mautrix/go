// Copyright 2025 Snowflake Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package floe

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

const (
	UPDATE_KATS = false
)

func TestSmoke_GCM256_IV256_64(t *testing.T) {
	p := FloeParams{
		Hash:      SHA384,
		Aead:      AesGcm256,
		IvLen:     32,
		EncSegLen: 64,
	}
	testParams(p, 2, "GCM256_IV256_64", t)
}

func TestSmoke_GCM256_IV256_4K(t *testing.T) {
	p := GCM256_IV256_4K()
	testParams(p, 2, "GCM256_IV256_4K", t)
}

func TestLongKeyInvalid(t *testing.T) {
	p := GCM256_IV256_4K()
	key := make([]byte, p.Aead.KeyLen())
	long_key := make([]byte, p.Aead.KeyLen()+1)
	enc, err := NewFloeEncryptor(p, long_key, nil)
	if enc != nil {
		t.Fatal("enc was expected to be nil")
	}
	if err == nil {
		t.Fatal("err was expected to be non-nil")
	}

	enc, err = NewFloeEncryptor(p, key, nil)
	if enc == nil {
		t.Fatal("enc was expected to be non-nil")
	}
	if err != nil {
		t.Fatal(err)
	}
	header := enc.Header
	dec, err := NewFloeDecryptor(p, long_key, nil, header)
	if dec != nil {
		t.Fatal("dec was expected to be nil")
	}
	if err == nil {
		t.Fatal("err was expected to be non-nil")
	}
}

func TestSmoke_GCM256_IV256_1M(t *testing.T) {
	p := GCM256_IV256_1M()
	testParams(p, 2, "GCM256_IV256_1M", t)
}

func TestSmoke_rotation(t *testing.T) {
	two := uint64(2)
	p := FloeParams{
		Hash:                 SHA384,
		Aead:                 AesGcm256,
		IvLen:                32,
		EncSegLen:            40,
		overrideMaskRotation: &two,
	}
	testParams(p, 10, "rotation", t)
}

func testParams(p FloeParams, segmentCount int, katName string, t *testing.T) {
	key := make([]byte, p.Aead.KeyLen())
	pt := make([]byte, segmentCount*p.PtSegLen()+3)
	_, err := rand.Read(pt)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("This is AAD")

	enc, err := NewFloeEncryptor(p, key, aad)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := enc.Header
	for offset := 0; offset < len(pt); offset += p.PtSegLen() {

		if len(pt)-offset <= p.PtSegLen() {
			// Last one!
			ct_seg, err := enc.EncryptLastSegment(pt[offset:])
			if err != nil {
				t.Fatal(err)
			}
			// t.Logf("Final Encrypted at offset %d: %s\n", offset, hex.EncodeToString(ct_seg))
			ciphertext = append(ciphertext, ct_seg...)
		} else {
			ct_seg, err := enc.EncryptSegment(pt[offset : offset+p.PtSegLen()])
			if err != nil {
				t.Fatal(err)
			}
			// t.Logf("Encrypted at offset %d: %s\n", offset, hex.EncodeToString(ct_seg))
			ciphertext = append(ciphertext, ct_seg...)
		}
	}
	t.Logf("Plaintext %s\n", hex.EncodeToString(pt))
	t.Logf("Ciphertext %s\n", hex.EncodeToString(ciphertext))
	// Time to decrypt!
	dec, err := NewFloeDecryptor(p, key, aad, ciphertext[:p.HeaderLen()])
	if err != nil {
		t.Fatal(err)
	}
	decrypted := make([]byte, 0)
	for offset := p.HeaderLen(); offset < len(ciphertext); offset += int(p.EncSegLen) {
		var ct_seg []byte
		var pt_seg []byte

		if len(ciphertext)-offset <= int(p.EncSegLen) {
			ct_seg = ciphertext[offset:]
			pt_seg, err = dec.DecryptLastSegment(ct_seg)
		} else {
			ct_seg = ciphertext[offset : offset+int(p.EncSegLen)]
			pt_seg, err = dec.DecryptSegment(ct_seg)
		}
		// t.Logf("Decrypting at offset %d, %s\n", offset, hex.EncodeToString(ct_seg))
		if err != nil {
			t.Fatal(err)
		}
		decrypted = append(decrypted, pt_seg...)

	}
	if !dec.IsDone() {
		t.Fatal("Decryption not done!")
	}
	if string(pt) != string(decrypted) {
		t.Fatalf("Decrypted plaintext does not match original plaintext: %s != %s\n", hex.EncodeToString(pt), hex.EncodeToString(decrypted))
	}

	if UPDATE_KATS {
		err := os.WriteFile("../kats/go_"+katName+"_pt.txt", []byte(hex.EncodeToString(pt)), 0644)
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile("../kats/go_"+katName+"_ct.txt", []byte(hex.EncodeToString(ciphertext)), 0644)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestEmptyPT(t *testing.T) {
	p := GCM256_IV256_4K()
	key := make([]byte, p.Aead.KeyLen())
	aad := make([]byte, 0)
	encryptor, err := NewFloeEncryptor(p, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	header := encryptor.Header
	lastSegmentCt, err := encryptor.EncryptLastSegment(make([]byte, 0))
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := NewFloeDecryptor(p, key, aad, header)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := decryptor.DecryptLastSegment(lastSegmentCt)
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted) != 0 {
		t.Fatalf("Decrypted empty ciphertext is not empty: %s\n", hex.EncodeToString(decrypted))
	}
}

func TestSegmentAligned(t *testing.T) {
	p := GCM256_IV256_4K()
	key := make([]byte, p.Aead.KeyLen())
	aad := make([]byte, 0)
	ptSeg := make([]byte, p.PtSegLen())
	encryptor, err := NewFloeEncryptor(p, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	header := encryptor.Header
	firstCt, err := encryptor.EncryptSegment(ptSeg)
	if err != nil {
		t.Fatal(err)
	}
	lastCt, err := encryptor.EncryptLastSegment(ptSeg)
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := NewFloeDecryptor(p, key, aad, header)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := decryptor.DecryptSegment(firstCt)
	if err != nil {
		t.Fatal(err)
	}
	if string(ptSeg) != string(decrypted) {
		t.Fatalf("Decrypted plaintext does not match original plaintext: %s != %s\n", hex.EncodeToString(ptSeg), hex.EncodeToString(decrypted))
	}
	decrypted, err = decryptor.DecryptLastSegment(lastCt)
	if err != nil {
		t.Fatal(err)
	}
	if string(ptSeg) != string(decrypted) {
		t.Fatalf("Decrypted plaintext does not match original plaintext: %s != %s\n", hex.EncodeToString(ptSeg), hex.EncodeToString(decrypted))
	}
}

func TestSegmentAlignedTrailingEmpty(t *testing.T) {
	p := GCM256_IV256_4K()
	key := make([]byte, p.Aead.KeyLen())
	aad := make([]byte, 0)
	ptSeg := make([]byte, p.PtSegLen())
	encryptor, err := NewFloeEncryptor(p, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	header := encryptor.Header
	firstCt, err := encryptor.EncryptSegment(ptSeg)
	if err != nil {
		t.Fatal(err)
	}
	lastCt, err := encryptor.EncryptLastSegment(make([]byte, 0))
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := NewFloeDecryptor(p, key, aad, header)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := decryptor.DecryptSegment(firstCt)
	if err != nil {
		t.Fatal(err)
	}
	if string(ptSeg) != string(decrypted) {
		t.Fatalf("Decrypted plaintext does not match original plaintext: %s != %s\n", hex.EncodeToString(ptSeg), hex.EncodeToString(decrypted))
	}
	decrypted, err = decryptor.DecryptLastSegment(lastCt)
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted) != 0 {
		t.Fatalf("Decrypted empty last segment is not empty: %s\n", hex.EncodeToString(decrypted))
	}
}

func decryptKat(p FloeParams, key, aad []byte, ciphertextHex, plaintextHex string, t *testing.T) {
	ciphertext, err := hex.DecodeString(strings.TrimSpace(ciphertextHex))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := hex.DecodeString(strings.TrimSpace(plaintextHex))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewFloeDecryptor(p, key, aad, ciphertext[:p.HeaderLen()])
	if err != nil {
		t.Fatal(err)
	}
	decrypted := make([]byte, 0)
	for offset := p.HeaderLen(); offset < len(ciphertext); offset += int(p.EncSegLen) {
		var ct_seg []byte
		var pt_seg []byte

		if len(ciphertext)-offset <= int(p.EncSegLen) {
			ct_seg = ciphertext[offset:]
			pt_seg, err = dec.DecryptLastSegment(ct_seg)
		} else {
			ct_seg = ciphertext[offset : offset+int(p.EncSegLen)]
			pt_seg, err = dec.DecryptSegment(ct_seg)
		}
		// t.Logf("Decrypting at offset %d, %s\n", offset, hex.EncodeToString(ct_seg))
		if err != nil {
			t.Fatal(err)
		}
		decrypted = append(decrypted, pt_seg...)

	}
	if string(pt) != string(decrypted) {
		t.Fatalf("Decrypted plaintext does not match original plaintext: %s != %s\n", hex.EncodeToString(pt), hex.EncodeToString(decrypted))
	}
}

func readKats(baseName string, t *testing.T) (string, string) {
	plaintextHex, err := os.ReadFile("../kats/" + baseName + "_pt.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertextHex, err := os.ReadFile("../kats/" + baseName + "_ct.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(plaintextHex), string(ciphertextHex)
}

func TestAllKats(t *testing.T) {
	t.Skip("Kats not available here")

	smallParams := FloeParams{
		Hash:      SHA384,
		Aead:      AesGcm256,
		IvLen:     32,
		EncSegLen: 64,
	}
	two := uint64(2)
	rotationParams := FloeParams{
		Hash:                 SHA384,
		Aead:                 AesGcm256,
		IvLen:                32,
		EncSegLen:            40,
		overrideMaskRotation: &two,
	}

	sources := []string{"go", "java", "pub_java", "cpp", "rust"}
	for _, source := range sources {
		t.Run(source+"_GCM256_IV256_4K", func(t *testing.T) {
			singleKatInnerTest(GCM256_IV256_4K(), source+"_GCM256_IV256_4K", t)
		})
		t.Run(source+"_GCM256_IV256_1M", func(t *testing.T) {
			singleKatInnerTest(GCM256_IV256_1M(), source+"_GCM256_IV256_1M", t)
		})
		t.Run(source+"_GCM256_IV256_64", func(t *testing.T) {
			singleKatInnerTest(smallParams, source+"_GCM256_IV256_64", t)
		})
		t.Run(source+"_rotation", func(t *testing.T) {
			singleKatInnerTest(rotationParams, source+"_rotation", t)
		})
	}

	// There are a few Java generated only KATs
	segmentTestParams := FloeParams{
		Hash:      SHA384,
		Aead:      AesGcm256,
		IvLen:     32,
		EncSegLen: 40,
	}
	singleKatInnerTest(segmentTestParams, "java_lastSegAligned", t)
	singleKatInnerTest(segmentTestParams, "java_lastSegEmpty", t)
}

func singleKatInnerTest(p FloeParams, source string, t *testing.T) {
	key := make([]byte, p.Aead.KeyLen())
	aad := []byte("This is AAD")
	plaintextHex, ciphertextHex := readKats(source, t)

	decryptKat(p, key, aad, ciphertextHex, string(plaintextHex), t)
}

func Benchmark1GBEncrypt(b *testing.B) {
	p := GCM256_IV256_1M()
	ptSegLen := p.PtSegLen()
	ptBuffer := make([]byte, ptSegLen)
	key := make([]byte, p.Aead.KeyLen())
	aad := make([]byte, 48)
	oneGB := 1024 * 1024 * 1024
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		written := 0
		floe, err := NewFloeEncryptor(p, key, aad)
		if err != nil {
			b.Fatal(err)
		}
		for written < oneGB {
			if oneGB-written < ptSegLen {
				remaining := ptBuffer[:oneGB-written]
				_, err = floe.EncryptLastSegment(remaining)
				if err != nil {
					b.Fatal(err)
				}
				written += len(remaining)
			} else {
				_, err = floe.EncryptSegment(ptBuffer)
				if err != nil {
					b.Fatal(err)
				}
				written += ptSegLen
			}
		}

	}
}

func Benchmark1GBDecrypt(b *testing.B) {
	p := GCM256_IV256_1M()
	ptSegLen := p.PtSegLen()
	ptBuffer := make([]byte, ptSegLen)
	key := make([]byte, p.Aead.KeyLen())
	aad := make([]byte, 48)
	oneGB := 1024 * 1024 * 1024
	ctFile, err := os.CreateTemp("", "floe_ct")
	if err != nil {
		b.Fatal(err)
	}
	defer ctFile.Close()
	defer os.Remove(ctFile.Name())

	written := 0
	floe, err := NewFloeEncryptor(p, key, aad)
	if err != nil {
		b.Fatal(err)
	}
	ctFile.Write(floe.Header)
	for written < oneGB {
		if oneGB-written < ptSegLen {
			remaining := ptBuffer[:oneGB-written]
			ct, err := floe.EncryptLastSegment(remaining)
			if err != nil {
				b.Fatal(err)
			}
			ctFile.Write(ct)
			if err != nil {
				b.Fatal(err)
			}
			written += len(remaining)
		} else {
			ct, err := floe.EncryptSegment(ptBuffer)
			if err != nil {
				b.Fatal(err)
			}
			ctFile.Write(ct)
			if err != nil {
				b.Fatal(err)
			}
			written += ptSegLen
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctFile.Seek(0, 0)
		header := make([]byte, p.HeaderLen())
		_, err = ctFile.Read(header)
		if err != nil {
			b.Fatal(err)
		}
		dec, err := NewFloeDecryptor(p, key, aad, header)
		offset := 0

		if err != nil {
			b.Fatal(err)
		}

		ctBuff := make([]byte, p.EncSegLen)
		for offset < oneGB {
			read, err := ctFile.Read(ctBuff)
			if err != nil {
				b.Fatal(err)
			}
			if read < int(p.EncSegLen) {
				// Last segment
				_, err = dec.DecryptLastSegment(ctBuff[:read])
				if err != nil {
					b.Fatal(err)
				}
				offset += read
			} else {
				_, err = dec.DecryptSegment(ctBuff)
				if err != nil {
					b.Fatal(err)
				}
				offset += int(p.EncSegLen)
			}
		}
	}
}
