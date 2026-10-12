package validator

import (
	"encoding/hex"
	"strings"

	"github.com/jphastings/ntag424/internal/crypto"
)

// Sign returns the values a tag holding key mirrors into a plain {{uid}},
// {{ctr}} and {{mac}} URL for this serial number and read count. It lets a
// server test its tap handling without a tag.
func Sign(uid []byte, counter uint32, key []byte) Values {
	ctr := counterLSB(counter)
	return Values{
		UID:     hexText(uid),
		Counter: hexText([]byte{ctr[2], ctr[1], ctr[0]}),
		MAC:     hexText(tapMAC(key, uid, ctr)),
	}
}

// SignEncrypted returns the values a tag holding key mirrors into an
// encrypted {{picc}} and {{mac}} URL for this serial number and read count.
// A real tag pads the encrypted data with random bytes; this pads with zeros.
func SignEncrypted(uid []byte, counter uint32, key []byte) Values {
	ctr := counterLSB(counter)
	plain := make([]byte, piccLen)
	plain[0] = 0xC0 | byte(len(uid)) // UID and counter both present
	copy(plain[1:], uid)
	copy(plain[1+len(uid):], ctr)
	return Values{
		PICC: hexText(crypto.CBCEncrypt(key, crypto.ZeroIV, plain)),
		MAC:  hexText(tapMAC(key, uid, ctr)),
	}
}

func counterLSB(counter uint32) []byte {
	return []byte{byte(counter), byte(counter >> 8), byte(counter >> 16)}
}

func hexText(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
