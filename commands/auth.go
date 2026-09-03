package commands

import (
	"bytes"
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/jphastings/ntag424/internal/crypto"
	"github.com/skythen/apdu"
)

// Errors returned by Authenticate and sendFull.
var (
	ErrNotAuthenticated = errors.New("not authenticated: call Authenticate first")
	ErrAuthFailed       = errors.New("authentication failed: card's response did not match")
	ErrResponseMAC      = errors.New("secure messaging response failed its MAC check")
	ErrInvalidKeyNo     = errors.New("key number must be 0-4")
	// ErrOldKeyRequired is returned by ChangeKey when replacing a key other
	// than the one just authenticated with, and oldKey is not a 16-byte
	// AES-128 key: the tag needs it to compute newKey XOR oldKey.
	ErrOldKeyRequired = errors.New("changing a different key requires its current 16-byte value")
)

// session holds the keys and counters negotiated by AuthenticateEV2First,
// used to secure subsequent CommMode.Full commands.
type session struct {
	encKey, macKey []byte
	ti             []byte // 4-byte transaction identifier
	ctr            uint16 // command counter, sent LSB-first
	keyNo          byte   // key number used to authenticate
}

// sessionVector builds SV1/SV2 as defined by AuthenticateEV2First, differing
// only in their two-byte prefix.
func sessionVector(p0, p1 byte, rndA, rndB []byte) []byte {
	sv := []byte{p0, p1, 0x00, 0x01, 0x00, 0x80}
	sv = append(sv, rndA[0:2]...)
	sv = append(sv, xorBytes(rndA[2:8], rndB[0:6])...)
	sv = append(sv, rndB[6:16]...)
	sv = append(sv, rndA[8:16]...)
	return sv
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// Authenticate performs AuthenticateEV2First with the given key number and
// 16-byte AES-128 key, establishing the secure messaging session used by
// WriteURL.
func (cp *CommandProcessor) Authenticate(keyNo byte, key []byte) error {
	if keyNo > 4 {
		return ErrInvalidKeyNo
	}
	if len(key) != 16 {
		return fmt.Errorf("key must be 16 bytes, got %d", len(key))
	}

	if err := cp.ISOSelectFile(SelectDirectoryByName(aidNDEF)); err != nil {
		return err
	}

	r, err := cp.card.SendCommandAPDU(&apdu.Capdu{
		Cla: 0x90, Ins: 0x71, P1: 0x00, P2: 0x00,
		Data: []byte{keyNo, 0x00},
		Ne:   apdu.MaxLenResponseDataStandard,
	})
	if err != nil {
		return fmt.Errorf("AuthenticateEV2First part 1: %w", err)
	}
	if r.SW1 != 0x91 || r.SW2 != 0xAF || len(r.Data) != 16 {
		return fmt.Errorf("AuthenticateEV2First part 1: unexpected response SW=%02X%02X len=%d", r.SW1, r.SW2, len(r.Data))
	}

	rndB := crypto.CBCDecrypt(key, crypto.ZeroIV, r.Data)

	rndA := make([]byte, 16)
	if _, err := io.ReadFull(cp.rand, rndA); err != nil {
		return fmt.Errorf("couldn't generate RndA: %w", err)
	}

	r, err = cp.card.SendCommandAPDU(&apdu.Capdu{
		Cla: 0x90, Ins: 0xAF, P1: 0x00, P2: 0x00,
		Data: crypto.CBCEncrypt(key, crypto.ZeroIV, append(append([]byte{}, rndA...), crypto.RotateLeft(rndB)...)),
		Ne:   apdu.MaxLenResponseDataStandard,
	})
	if err != nil {
		return fmt.Errorf("AuthenticateEV2First part 2: %w", err)
	}
	if r.SW1 != 0x91 || r.SW2 != 0x00 || len(r.Data) != 32 {
		return fmt.Errorf("AuthenticateEV2First part 2: unexpected response SW=%02X%02X len=%d", r.SW1, r.SW2, len(r.Data))
	}

	plain := crypto.CBCDecrypt(key, crypto.ZeroIV, r.Data)
	ti := plain[0:4]
	rndAResp := plain[4:20]
	if subtle.ConstantTimeCompare(rndAResp, crypto.RotateLeft(rndA)) != 1 {
		return ErrAuthFailed
	}

	cp.session = &session{
		encKey: crypto.CMAC(key, sessionVector(0xA5, 0x5A, rndA, rndB)),
		macKey: crypto.CMAC(key, sessionVector(0x5A, 0xA5, rndA, rndB)),
		ti:     append([]byte{}, ti...),
		ctr:    0,
		keyNo:  keyNo,
	}

	return nil
}

// sendFull sends cmd with header and data under CommMode.Full: AES-CBC
// encrypted and CMAC protected, per the negotiated session. It returns the
// decrypted response data, if any.
func (cp *CommandProcessor) sendFull(cmd byte, header, data []byte) ([]byte, error) {
	return cp.sendFullOpt(cmd, header, data, true)
}

// sendFullOpt is sendFull with control over whether the card is expected to
// MAC its reply. ChangeKey's case B (changing the very key just authenticated
// with) gets a bare 9100 back: the tag no longer holds the session keys
// needed to sign one. With expectRespMAC false, the response is returned
// as-is, unverified and undecrypted, but the command counter still advances.
func (cp *CommandProcessor) sendFullOpt(cmd byte, header, data []byte, expectRespMAC bool) ([]byte, error) {
	if cp.session == nil {
		return nil, ErrNotAuthenticated
	}
	s := cp.session

	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		return nil, err
	}

	ctrLE := make([]byte, 2)
	binary.LittleEndian.PutUint16(ctrLE, s.ctr)

	ivc := make([]byte, aes.BlockSize)
	block.Encrypt(ivc, bytes.Join([][]byte{{0xA5, 0x5A}, s.ti, ctrLE, make([]byte, 8)}, nil))

	enc := crypto.CBCEncrypt(s.encKey, ivc, crypto.Pad(data))

	macInput := bytes.Join([][]byte{{cmd}, ctrLE, s.ti, header, enc}, nil)
	mact := crypto.TruncateMAC(crypto.CMAC(s.macKey, macInput))

	r, err := cp.card.SendCommandAPDU(&apdu.Capdu{
		Cla: 0x90, Ins: cmd, P1: 0x00, P2: 0x00,
		Data: bytes.Join([][]byte{header, enc, mact}, nil),
		Ne:   apdu.MaxLenResponseDataStandard,
	})
	if err != nil {
		return nil, err
	}

	s.ctr++
	binary.LittleEndian.PutUint16(ctrLE, s.ctr)

	if !expectRespMAC {
		return r.Data, nil
	}

	if len(r.Data) < 8 {
		return nil, fmt.Errorf("secure messaging response too short: %d bytes", len(r.Data))
	}
	respEnc := r.Data[:len(r.Data)-8]
	respMAC := r.Data[len(r.Data)-8:]

	expected := crypto.TruncateMAC(crypto.CMAC(s.macKey, bytes.Join([][]byte{{r.SW2}, ctrLE, s.ti, respEnc}, nil)))
	if subtle.ConstantTimeCompare(expected, respMAC) != 1 {
		return nil, ErrResponseMAC
	}

	if len(respEnc) == 0 {
		return nil, nil
	}

	ivr := make([]byte, aes.BlockSize)
	block.Encrypt(ivr, bytes.Join([][]byte{{0x5A, 0xA5}, s.ti, ctrLE, make([]byte, 8)}, nil))

	return crypto.Unpad(crypto.CBCDecrypt(s.encKey, ivr, respEnc)), nil
}
