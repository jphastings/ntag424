// Package crypto provides the AES primitives NTAG 424 DNA secure messaging
// and Secure Dynamic Messaging need: CBC encryption/decryption, CMAC, and
// their supporting padding and truncation helpers.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

// ZeroIV is the all-zero initialization vector used throughout NTAG 424 DNA
// secure messaging.
var ZeroIV = make([]byte, aes.BlockSize)

// CBCEncrypt encrypts data with AES-CBC under key and iv.
func CBCEncrypt(key, iv, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return out
}

// CBCDecrypt decrypts data with AES-CBC under key and iv.
func CBCDecrypt(key, iv, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out
}

// Pad implements ISO/IEC 9797-1 padding method 2: append 0x80, then zero-pad
// to the next block boundary. Always adds at least one byte, even to
// already-aligned data (AN12196 Table 18 pads a 128-byte payload to 144).
func Pad(data []byte) []byte {
	padded := append(append([]byte{}, data...), 0x80)
	for len(padded)%aes.BlockSize != 0 {
		padded = append(padded, 0x00)
	}
	return padded
}

// Unpad removes ISO/IEC 9797-1 method 2 padding.
func Unpad(data []byte) []byte {
	i := len(data)
	for i > 0 && data[i-1] == 0x00 {
		i--
	}
	if i > 0 && data[i-1] == 0x80 {
		i--
	}
	return data[:i]
}

// RotateLeft rotates b one byte to the left.
func RotateLeft(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b[1:])
	out[len(b)-1] = b[0]
	return out
}

// TruncateMAC returns the 8 bytes of a 16-byte CMAC at odd indices, as used
// throughout NTAG 424 DNA secure messaging.
func TruncateMAC(mac []byte) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = mac[2*i+1]
	}
	return out
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// shiftLeft treats b as a big-endian bit string and shifts it left by one
// bit, discarding the overflow bit but returning it as the return value.
func shiftLeft(b []byte) (shifted []byte, carry byte) {
	out := make([]byte, len(b))
	for i := len(b) - 1; i >= 0; i-- {
		out[i] = (b[i] << 1) | carry
		carry = b[i] >> 7
	}
	return out, carry
}

func cmacSubkey(k []byte) []byte {
	shifted, carry := shiftLeft(k)
	if carry == 1 {
		shifted[len(shifted)-1] ^= 0x87
	}
	return shifted
}

// CMAC computes AES-CMAC per RFC 4493 / NIST SP 800-38B.
func CMAC(key, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	l := make([]byte, aes.BlockSize)
	block.Encrypt(l, l)
	k1 := cmacSubkey(l)
	k2 := cmacSubkey(k1)

	var blocks []byte
	if len(msg) != 0 && len(msg)%aes.BlockSize == 0 {
		blocks = append(blocks, msg...)
		last := len(blocks) - aes.BlockSize
		copy(blocks[last:], xorBytes(blocks[last:], k1))
	} else {
		blocks = Pad(msg)
		last := len(blocks) - aes.BlockSize
		copy(blocks[last:], xorBytes(blocks[last:], k2))
	}

	x := make([]byte, aes.BlockSize)
	for i := 0; i < len(blocks); i += aes.BlockSize {
		x = xorBytes(x, blocks[i:i+aes.BlockSize])
		next := make([]byte, aes.BlockSize)
		block.Encrypt(next, x)
		x = next
	}
	return x
}
