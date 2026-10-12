// Package validator checks a URL produced by an NTAG 424 DNA tap against the
// Secure Dynamic Messaging template it should have come from, verifying the
// tag's signature without needing to talk to a card.
package validator

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jphastings/ntag424/internal/crypto"
	"github.com/jphastings/ntag424/internal/mirror"
)

// Lengths of each mirror value once expanded, in hex characters / decoded bytes.
const (
	uidHexLen  = 14
	uidLen     = 7
	ctrHexLen  = 6
	ctrLen     = 3
	piccHexLen = 32
	piccLen    = 16
	macHexLen  = 16
	macLen     = 8
)

// Tap is the verified content of a single tap.
type Tap struct {
	UID     []byte // the tag's serial number
	Counter uint32 // how many times the tag has been read
}

// Values are the mirror values as they appear in a tap URL, in hexadecimal text.
// Leave a field empty when the tag does not mirror it.
type Values struct {
	UID, Counter, PICC, MAC string
}

// Errors returned by VerifyURL and Verify.
var (
	ErrMACMismatch      = errors.New("signature does not match: this tap is not from a tag holding this key")
	ErrTemplateMismatch = errors.New("URL does not match the template it should have come from")
	ErrMissingMAC       = errors.New("no signature to check")
	ErrMissingIdentity  = errors.New("no {{uid}} or {{picc}} value to identify the tag")
	ErrMalformed        = errors.New("mirror value is not valid hexadecimal of the expected length")
)

// VerifyURL checks a URL produced by a tap against the template that was written to the tag.
func VerifyURL(tapURL, template string, key []byte) (*Tap, error) {
	expanded, positions, err := mirror.Expand(template)
	if err != nil {
		return nil, err
	}

	if len(tapURL) != len(expanded) {
		return nil, ErrTemplateMismatch
	}

	runs := placeholderRuns(positions)
	// A character outside every placeholder run has to match the template
	// exactly, so a URL from a different host or path fails even when its
	// signature is well formed.
	for i := 0; i < len(expanded); i++ {
		if inRun(runs, i) {
			continue
		}
		if tapURL[i] != expanded[i] {
			return nil, ErrTemplateMismatch
		}
	}

	v := Values{}
	if positions.UID >= 0 {
		v.UID = tapURL[positions.UID : positions.UID+uidHexLen]
	}
	if positions.Counter >= 0 {
		v.Counter = tapURL[positions.Counter : positions.Counter+ctrHexLen]
	}
	if positions.PICC >= 0 {
		v.PICC = tapURL[positions.PICC : positions.PICC+piccHexLen]
	}
	if positions.MAC >= 0 {
		v.MAC = tapURL[positions.MAC : positions.MAC+macHexLen]
	}

	return Verify(v, key)
}

type run struct{ start, end int }

func placeholderRuns(p mirror.Positions) []run {
	var runs []run
	if p.UID >= 0 {
		runs = append(runs, run{p.UID, p.UID + uidHexLen})
	}
	if p.Counter >= 0 {
		runs = append(runs, run{p.Counter, p.Counter + ctrHexLen})
	}
	if p.PICC >= 0 {
		runs = append(runs, run{p.PICC, p.PICC + piccHexLen})
	}
	if p.MAC >= 0 {
		runs = append(runs, run{p.MAC, p.MAC + macHexLen})
	}
	return runs
}

func inRun(runs []run, i int) bool {
	for _, r := range runs {
		if i >= r.start && i < r.end {
			return true
		}
	}
	return false
}

func decodeFixed(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, ErrMalformed
	}
	return b, nil
}

// Verify checks mirror values that have already been taken out of a URL, for example from query parameters.
func Verify(v Values, key []byte) (*Tap, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes, got %d", len(key))
	}

	if v.MAC == "" {
		return nil, ErrMissingMAC
	}
	mac, err := decodeFixed(v.MAC, macLen)
	if err != nil {
		return nil, err
	}

	var uid, counterBytes []byte
	if v.PICC != "" {
		picc, err := decodeFixed(v.PICC, piccLen)
		if err != nil {
			return nil, err
		}
		plain := crypto.CBCDecrypt(key, crypto.ZeroIV, picc)

		tag := plain[0]
		if tag&0x80 == 0 {
			return nil, ErrMalformed
		}
		piccUIDLen := int(tag & 0x0F)
		hasCounter := tag&0x40 != 0
		need := 1 + piccUIDLen
		if hasCounter {
			need += 3
		}
		if need > len(plain) {
			return nil, ErrMalformed
		}

		uid = plain[1 : 1+piccUIDLen]
		if hasCounter {
			counterBytes = plain[1+piccUIDLen : 1+piccUIDLen+3]
		}
	} else {
		if v.UID == "" {
			return nil, ErrMissingIdentity
		}
		uid, err = decodeFixed(v.UID, uidLen)
		if err != nil {
			return nil, err
		}

		if v.Counter != "" {
			raw, err := decodeFixed(v.Counter, ctrLen)
			if err != nil {
				return nil, err
			}
			// The URL renders the counter most significant byte first, but
			// the signing input needs it least significant byte first.
			counterBytes = []byte{raw[2], raw[1], raw[0]}
		}
	}

	expected := tapMAC(key, uid, counterBytes)

	if subtle.ConstantTimeCompare(expected, mac) != 1 {
		return nil, ErrMACMismatch
	}

	var counter uint32
	if len(counterBytes) == 3 {
		counter = uint32(counterBytes[0]) | uint32(counterBytes[1])<<8 | uint32(counterBytes[2])<<16
	}

	return &Tap{UID: uid, Counter: counter}, nil
}

// tapMAC is the signature a tag holding key writes for this serial number and
// counter. The counter is least significant byte first, and empty when the tag
// doesn't mirror one.
func tapMAC(key, uid, counterLSB []byte) []byte {
	sv2 := []byte{0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80}
	sv2 = append(sv2, uid...)
	sv2 = append(sv2, counterLSB...)
	for len(sv2)%16 != 0 {
		sv2 = append(sv2, 0x00)
	}
	return crypto.TruncateMAC(crypto.CMAC(crypto.CMAC(key, sv2), nil))
}
