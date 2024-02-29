package account_test

import "github.com/element-hq/mautrix-go/crypto/goolm/crypto"

var pickledDataFromLibOlm = []byte("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")
var expectedEd25519KeyPairPickleLibOLM = crypto.Ed25519KeyPair{
	PublicKey:  []byte{237, 217, 234, 95, 181, 217, 229, 96, 41, 51, 153, 83, 191, 158, 47, 242, 100, 163, 120, 171, 15, 117, 176, 58, 70, 181, 5, 53, 64, 26, 99, 55},
	PrivateKey: []byte{232, 245, 108, 122, 156, 40, 107, 206, 71, 27, 156, 60, 52, 126, 39, 215, 255, 217, 81, 248, 206, 228, 153, 244, 31, 114, 88, 127, 207, 250, 255, 122, 196, 207, 3, 96, 142, 227, 172, 88, 13, 230, 140, 125, 200, 220, 19, 127, 144, 79, 32, 249, 135, 238, 3, 205, 227, 73, 250, 219, 223, 248, 175, 20},
}
var expectedCurve25519KeyPairPickleLibOLM = crypto.Curve25519KeyPair{
	PublicKey:  []byte{56, 193, 217, 134, 124, 49, 9, 185, 241, 26, 246, 132, 245, 34, 222, 189, 199, 201, 136, 80, 185, 153, 132, 240, 194, 48, 30, 157, 74, 1, 243, 0},
	PrivateKey: []byte{80, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
}
var expectedOTKeysPickleLibOLM = []crypto.OneTimeKey{
	{ID: 42,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{41, 72, 49, 87, 49, 27, 143, 250, 203, 35, 151, 49, 248, 200, 99, 225, 101, 68, 203, 251, 132, 115, 253, 59, 21, 61, 111, 58, 252, 200, 85, 61},
			PrivateKey: []byte{80, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43},
		},
	},
	{ID: 41,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{123, 42, 55, 123, 233, 87, 88, 76, 17, 249, 112, 97, 226, 213, 73, 239, 49, 217, 168, 220, 180, 182, 176, 231, 77, 138, 92, 58, 62, 185, 250, 12},
			PrivateKey: []byte{80, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42},
		},
	},
	{ID: 40,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{139, 80, 115, 105, 78, 90, 82, 35, 21, 248, 232, 10, 8, 237, 95, 201, 73, 219, 244, 105, 35, 184, 225, 56, 164, 142, 79, 59, 178, 51, 150, 69},
			PrivateKey: []byte{80, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41},
		},
	},
	{ID: 39,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{176, 111, 229, 19, 195, 233, 77, 12, 228, 241, 254, 193, 139, 127, 150, 20, 182, 36, 103, 30, 207, 5, 35, 93, 60, 81, 53, 133, 216, 4, 81, 94},
			PrivateKey: []byte{80, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40},
		},
	},
	{ID: 38,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{137, 106, 140, 51, 49, 76, 42, 164, 198, 184, 58, 9, 246, 119, 84, 88, 196, 199, 189, 145, 145, 141, 209, 29, 68, 64, 171, 23, 126, 11, 220, 122},
			PrivateKey: []byte{80, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39},
		},
	},
	{ID: 37,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{38, 99, 240, 40, 17, 97, 91, 79, 105, 102, 81, 153, 12, 175, 81, 4, 132, 171, 246, 96, 10, 162, 71, 175, 241, 23, 22, 129, 38, 15, 230, 67},
			PrivateKey: []byte{80, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38},
		},
	},
	{ID: 36,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{205, 28, 163, 27, 148, 116, 82, 169, 230, 7, 184, 192, 76, 177, 196, 129, 62, 32, 76, 145, 247, 56, 220, 180, 74, 193, 205, 178, 158, 209, 168, 123},
			PrivateKey: []byte{80, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37},
		},
	},
	{ID: 35,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{195, 125, 80, 132, 106, 120, 250, 0, 145, 191, 116, 179, 167, 91, 65, 10, 121, 19, 12, 51, 78, 229, 170, 110, 37, 37, 109, 65, 221, 126, 168, 5},
			PrivateKey: []byte{80, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36},
		},
	},
	{ID: 34,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{93, 0, 88, 212, 33, 219, 129, 18, 103, 142, 90, 217, 6, 84, 99, 224, 41, 78, 245, 65, 65, 70, 116, 194, 23, 28, 21, 40, 220, 202, 139, 8},
			PrivateKey: []byte{80, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35},
		},
	},
	{ID: 33,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{158, 245, 92, 234, 230, 162, 236, 226, 172, 246, 255, 113, 231, 162, 211, 19, 141, 244, 36, 127, 235, 47, 38, 209, 7, 107, 245, 147, 161, 89, 246, 53},
			PrivateKey: []byte{80, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34},
		},
	},
	{ID: 32,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{69, 20, 138, 120, 68, 160, 34, 99, 205, 177, 138, 147, 96, 118, 36, 239, 206, 11, 118, 75, 170, 216, 193, 108, 24, 65, 0, 131, 226, 73, 22, 18},
			PrivateKey: []byte{80, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33},
		},
	},
	{ID: 31,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{201, 153, 194, 8, 6, 146, 167, 134, 209, 163, 215, 61, 114, 191, 150, 68, 205, 106, 37, 144, 32, 216, 19, 210, 139, 169, 221, 28, 160, 193, 196, 71},
			PrivateKey: []byte{80, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32},
		},
	},
	{ID: 30,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{211, 29, 161, 172, 192, 112, 209, 226, 113, 120, 177, 145, 108, 134, 92, 21, 31, 29, 162, 237, 77, 179, 96, 247, 123, 246, 47, 40, 238, 242, 206, 53},
			PrivateKey: []byte{80, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31},
		},
	},
	{ID: 29,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{197, 144, 16, 124, 25, 208, 46, 163, 33, 56, 116, 172, 53, 106, 42, 217, 240, 152, 165, 10, 82, 218, 96, 237, 211, 254, 229, 209, 5, 154, 52, 21},
			PrivateKey: []byte{80, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
		},
	},
	{ID: 28,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{42, 188, 228, 224, 227, 132, 230, 252, 175, 213, 113, 132, 226, 151, 138, 166, 213, 151, 235, 1, 4, 81, 45, 80, 27, 140, 195, 234, 136, 163, 245, 96},
			PrivateKey: []byte{80, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29},
		},
	},
	{ID: 27,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{153, 0, 67, 133, 177, 241, 105, 219, 32, 58, 135, 239, 145, 124, 122, 32, 137, 109, 40, 177, 54, 85, 46, 69, 231, 253, 146, 150, 228, 172, 9, 66},
			PrivateKey: []byte{80, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
		},
	},
	{ID: 26,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{3, 79, 232, 39, 90, 120, 71, 216, 193, 102, 132, 48, 91, 225, 8, 229, 99, 206, 128, 110, 9, 161, 75, 204, 86, 250, 54, 185, 152, 163, 144, 124},
			PrivateKey: []byte{80, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27},
		},
	},
	{ID: 25,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{96, 21, 62, 175, 244, 249, 33, 134, 162, 32, 142, 56, 215, 27, 12, 30, 229, 118, 63, 40, 45, 120, 204, 134, 111, 95, 21, 150, 112, 60, 187, 111},
			PrivateKey: []byte{80, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26},
		},
	},
	{ID: 24,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{103, 239, 218, 49, 88, 55, 161, 63, 238, 39, 114, 106, 175, 158, 59, 43, 39, 112, 239, 175, 29, 174, 75, 172, 9, 84, 230, 109, 214, 77, 170, 124},
			PrivateKey: []byte{80, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25},
		},
	},
	{ID: 23,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{35, 148, 228, 98, 0, 124, 196, 15, 5, 63, 73, 127, 52, 126, 165, 175, 186, 35, 196, 89, 94, 233, 56, 60, 103, 125, 67, 47, 29, 132, 206, 13},
			PrivateKey: []byte{80, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24},
		},
	},
	{ID: 22,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{94, 143, 132, 227, 112, 122, 177, 213, 30, 87, 21, 85, 0, 193, 221, 87, 111, 100, 99, 15, 50, 68, 92, 146, 222, 179, 182, 58, 136, 235, 74, 44},
			PrivateKey: []byte{80, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23},
		},
	},
	{ID: 21,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{232, 20, 27, 90, 55, 105, 146, 28, 107, 129, 73, 107, 1, 35, 70, 190, 227, 54, 169, 214, 160, 99, 150, 180, 37, 109, 115, 211, 84, 115, 91, 73},
			PrivateKey: []byte{80, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22},
		},
	},
	{ID: 20,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{245, 105, 178, 42, 165, 43, 232, 76, 48, 163, 5, 3, 42, 123, 59, 208, 74, 227, 36, 112, 77, 212, 203, 152, 81, 228, 226, 69, 45, 101, 182, 65},
			PrivateKey: []byte{80, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21},
		},
	},
	{ID: 19,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{16, 18, 85, 33, 104, 88, 95, 252, 135, 25, 55, 255, 240, 198, 30, 251, 163, 44, 150, 111, 155, 150, 143, 163, 242, 186, 142, 145, 59, 14, 161, 50},
			PrivateKey: []byte{80, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20},
		},
	},
	{ID: 18,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{32, 138, 232, 106, 32, 165, 39, 122, 146, 194, 126, 235, 84, 72, 127, 106, 83, 32, 219, 45, 201, 36, 226, 133, 201, 67, 168, 199, 112, 73, 166, 68},
			PrivateKey: []byte{80, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19},
		},
	},
	{ID: 17,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{10, 231, 214, 54, 36, 71, 42, 193, 204, 235, 148, 182, 60, 82, 228, 215, 61, 218, 146, 65, 227, 136, 233, 11, 223, 88, 95, 113, 47, 84, 169, 53},
			PrivateKey: []byte{80, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18},
		},
	},
	{ID: 16,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{226, 60, 255, 91, 122, 150, 74, 95, 227, 250, 237, 107, 205, 242, 56, 123, 52, 25, 65, 125, 69, 255, 101, 60, 201, 140, 196, 213, 196, 75, 109, 92},
			PrivateKey: []byte{80, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17},
		},
	},
	{ID: 15,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{171, 229, 71, 9, 133, 66, 150, 143, 73, 156, 11, 216, 148, 7, 153, 129, 237, 207, 228, 193, 55, 183, 156, 178, 132, 85, 154, 43, 19, 29, 170, 127},
			PrivateKey: []byte{80, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
		},
	},
	{ID: 14,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{53, 241, 2, 154, 223, 221, 222, 131, 114, 196, 111, 189, 26, 210, 20, 48, 39, 57, 199, 192, 2, 239, 213, 135, 232, 160, 92, 214, 18, 18, 205, 93},
			PrivateKey: []byte{80, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15},
		},
	},
	{ID: 13,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{92, 15, 157, 2, 49, 70, 253, 32, 39, 210, 54, 167, 55, 95, 255, 118, 76, 52, 184, 76, 185, 217, 31, 84, 7, 118, 1, 117, 53, 78, 216, 91},
			PrivateKey: []byte{80, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14},
		},
	},
	{ID: 12,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{67, 94, 86, 147, 61, 140, 71, 173, 0, 97, 202, 174, 242, 37, 198, 173, 214, 104, 89, 37, 204, 136, 32, 62, 166, 165, 56, 194, 242, 26, 79, 12},
			PrivateKey: []byte{80, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13},
		},
	},
	{ID: 11,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{147, 197, 91, 58, 183, 17, 72, 41, 244, 222, 191, 70, 195, 238, 110, 223, 135, 107, 108, 43, 154, 144, 50, 20, 222, 69, 42, 214, 69, 181, 0, 82},
			PrivateKey: []byte{80, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12},
		},
	},
	{ID: 10,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{116, 144, 19, 88, 33, 120, 92, 138, 174, 218, 192, 222, 96, 249, 46, 250, 4, 197, 250, 196, 243, 68, 183, 210, 218, 107, 206, 138, 121, 226, 189, 104},
			PrivateKey: []byte{80, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11},
		},
	},
	{ID: 9,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{140, 220, 222, 205, 238, 56, 126, 139, 40, 172, 222, 189, 235, 73, 50, 238, 125, 114, 73, 193, 80, 87, 86, 82, 205, 247, 206, 222, 164, 151, 1, 110},
			PrivateKey: []byte{80, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10},
		},
	},
	{ID: 8,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{129, 168, 225, 128, 194, 202, 63, 189, 162, 243, 79, 88, 251, 222, 173, 19, 132, 217, 193, 192, 171, 149, 159, 128, 244, 136, 216, 28, 2, 175, 141, 7},
			PrivateKey: []byte{80, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
		},
	},
	{ID: 7,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{44, 161, 77, 24, 61, 118, 178, 112, 31, 10, 14, 217, 0, 66, 161, 88, 134, 88, 53, 74, 93, 62, 211, 217, 87, 203, 122, 143, 239, 1, 24, 121},
			PrivateKey: []byte{80, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8},
		},
	},
	{ID: 6,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{167, 86, 75, 53, 54, 151, 106, 235, 48, 47, 54, 144, 180, 160, 209, 24, 78, 99, 57, 76, 109, 162, 233, 213, 170, 121, 37, 203, 178, 212, 130, 0},
			PrivateKey: []byte{80, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7},
		},
	},
	{ID: 5,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{194, 48, 135, 21, 239, 220, 32, 235, 254, 154, 245, 120, 129, 44, 108, 62, 246, 57, 62, 197, 170, 228, 107, 136, 155, 186, 29, 25, 57, 65, 172, 88},
			PrivateKey: []byte{80, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6},
		},
	},
	{ID: 4,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{85, 201, 136, 56, 1, 248, 140, 74, 234, 124, 137, 178, 244, 178, 37, 163, 73, 220, 116, 243, 236, 92, 198, 246, 111, 99, 227, 90, 106, 115, 9, 70},
			PrivateKey: []byte{80, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
		},
	},
	{ID: 3,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{38, 244, 146, 200, 126, 125, 48, 184, 222, 106, 254, 236, 231, 113, 26, 128, 84, 137, 162, 163, 97, 54, 213, 96, 254, 23, 55, 178, 114, 105, 93, 83},
			PrivateKey: []byte{80, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
		},
	},
	{ID: 2,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{149, 218, 194, 83, 219, 185, 224, 51, 177, 226, 224, 190, 219, 150, 131, 5, 183, 52, 226, 205, 114, 116, 219, 156, 227, 175, 66, 165, 132, 8, 24, 82},
			PrivateKey: []byte{80, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
		},
	},
	{ID: 1,
		Key: crypto.Curve25519KeyPair{
			PublicKey:  []byte{215, 133, 170, 227, 69, 234, 37, 45, 63, 251, 88, 239, 181, 64, 54, 203, 166, 87, 83, 33, 234, 207, 136, 145, 71, 153, 36, 239, 125, 151, 69, 106},
			PrivateKey: []byte{80, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		},
	},
}
