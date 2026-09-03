package commands

import (
	"encoding/binary"
	"errors"

	"github.com/hsanjuan/go-ndef"
	"github.com/jphastings/ntag424/internal/mirror"
)

// Placeholders the tag replaces at read time. Each expands to the ASCII-hex length the tag writes.
const (
	MirrorUID     = mirror.UID     // 14 hex chars: the 7-byte UID
	MirrorCounter = mirror.Counter // 6 hex chars: the 3-byte read counter (LSB first)
	MirrorPICC    = mirror.PICC    // 32 hex chars: AES-encrypted UID + counter; cannot be combined with {{uid}} or {{ctr}}
	MirrorMAC     = mirror.MAC     // 16 hex chars: truncated AES-CMAC
)

// Errors returned by ParseURL.
var (
	ErrUnknownMirror      = mirror.ErrUnknown
	ErrDuplicateMirror    = mirror.ErrDuplicate
	ErrMirrorConflict     = mirror.ErrConflict
	ErrMACWithoutIdentity = mirror.ErrMACWithoutIdentity
)

// Errors returned by WriteURL.
var (
	// ErrReadLimitTooLarge is returned when WithReadLimit's n doesn't fit in
	// the 3-byte SDMReadCtrLimit field.
	ErrReadLimitTooLarge = errors.New("read limit exceeds 0xFFFFFF, the field is 3 bytes")
	// ErrReadLimitZero is returned for WithReadLimit(0). A zero limit makes
	// the tag unreadable as soon as the settings are written, and 0 is far
	// more likely to be an uninitialised variable than a deliberate choice.
	ErrReadLimitZero = errors.New("read limit is zero, which would make the tag unreadable immediately")
	// ErrReadLimitNeedsMirror is returned when WithReadLimit is used with a
	// URL that has no SDM mirror placeholders: a read limit requires SDM to
	// be enabled, which an all-static URL leaves off.
	ErrReadLimitNeedsMirror = errors.New("read limit requires at least one SDM mirror placeholder in the URL")
)

// Layout is a URL with its placeholders expanded, and the byte offset of each mirror within the NDEF file
// (counted from the start of the file, so the two-byte NDEF length prefix is included), as ChangeFileSettings expects.
// An offset of -1 means that mirror is not used.
type Layout struct {
	URL                     string
	UID, Counter, PICC, MAC int
}

// ParseURL expands the SDM mirror placeholders in url and locates the file offset of each.
func ParseURL(url string) (Layout, error) {
	expanded, positions, err := mirror.Expand(url)
	if err != nil {
		return Layout{}, err
	}

	marshalled, err := ndef.NewURIMessage(expanded).Marshal()
	if err != nil {
		return Layout{}, err
	}
	if 2+len(marshalled) > 256 {
		return Layout{}, ErrNDEFTooLong
	}

	// NewURIMessage's payload ends with the URL body (any matched well-known prefix,
	// e.g. "https://", is replaced by a single identifier byte earlier in the payload),
	// so a character's file offset is a fixed distance from the end of the marshalled
	// record, based on its distance from the end of the expanded URL.
	base := 2 + len(marshalled) - len(expanded)

	l := Layout{URL: expanded, UID: -1, Counter: -1, PICC: -1, MAC: -1}
	if positions.UID >= 0 {
		l.UID = base + positions.UID
	}
	if positions.Counter >= 0 {
		l.Counter = base + positions.Counter
	}
	if positions.PICC >= 0 {
		l.PICC = base + positions.PICC
	}
	if positions.MAC >= 0 {
		l.MAC = base + positions.MAC
	}

	return l, nil
}

// hasMirror reports whether l uses any SDM mirror placeholder.
func (l Layout) hasMirror() bool {
	return l.UID != -1 || l.Counter != -1 || l.PICC != -1 || l.MAC != -1
}

// fileSettings builds the ChangeFileSettings command data configuring the NDEF file for l's SDM layout.
// readLimit, if non-nil, sets SDMReadCtrLimit to *readLimit.
func fileSettings(l Layout, keyNo byte, readLimit *uint32) []byte {
	if !l.hasMirror() {
		return []byte{0x00, 0xE0, 0xEE}
	}

	sdmOptions := byte(0x01)
	if l.UID != -1 || l.PICC != -1 {
		sdmOptions |= 0x80
	}
	if l.Counter != -1 || l.PICC != -1 {
		sdmOptions |= 0x40
	}
	if readLimit != nil {
		sdmOptions |= 0x20
	}

	meta := byte(0xF)
	switch {
	case l.PICC != -1:
		meta = keyNo
	case l.UID != -1 || l.Counter != -1:
		meta = 0xE
	}
	file := byte(0xF)
	if l.MAC != -1 {
		file = keyNo
	}

	data := []byte{0x40, 0xE0, 0xEE, sdmOptions, 0xF0 | keyNo, (meta << 4) | file}

	appendOffset := func(off int) {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(off))
		data = append(data, b[:3]...)
	}

	if l.UID != -1 {
		appendOffset(l.UID)
	}
	if l.Counter != -1 {
		appendOffset(l.Counter)
	}
	if l.PICC != -1 {
		appendOffset(l.PICC)
	}
	if l.MAC != -1 {
		// SDMMACInputOffset and SDMMACOffset are both set to the MAC offset: the MAC
		// input is empty, matching AN12196 and the sdm-backend verifier.
		appendOffset(l.MAC)
		appendOffset(l.MAC)
	}

	if readLimit != nil {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, *readLimit)
		data = append(data, b[:3]...)
	}

	return data
}

// WriteOption adjusts how WriteURL configures the tag.
type WriteOption func(*writeConfig)

type writeConfig struct {
	readLimit    uint32
	hasReadLimit bool
}

// WithReadLimit stops the tag from serving its NDEF file to unauthenticated
// readers once its read counter reaches n. Such a reader then gets an error
// from both Cmd.ReadData and Cmd.ISOReadBinary, so an ordinary phone sees
// nothing at all, not even the fixed part of the URL. Because any tag that can
// be tapped can be tapped n times deliberately, NXP's AN12196 (section 7.6)
// calls this a potential denial-of-service risk.
//
// A reader holding the key is not affected: the NT4H2421Gx data sheet
// (section 9.3.2) states that reading is always possible when authenticated.
// Authenticate and call WriteURL again without this option to lift the limit.
//
// The counter itself only counts up. Writing new settings while Secure Dynamic
// Messaging is already enabled does not reset it (confirmed on hardware).
func WithReadLimit(n uint32) WriteOption {
	return func(c *writeConfig) {
		c.readLimit = n
		c.hasReadLimit = true
	}
}

// WriteURL configures the tag's NDEF file for Secure Dynamic Messaging with sdmKeyNo,
// then writes url with its mirror placeholders expanded. Authenticate must be called
// before each WriteURL: writing the file ends the tag's authenticated session.
func (cp *CommandProcessor) WriteURL(url string, sdmKeyNo byte, opts ...WriteOption) error {
	if sdmKeyNo > 4 {
		return ErrInvalidKeyNo
	}

	var cfg writeConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.hasReadLimit {
		if cfg.readLimit > 0xFFFFFF {
			return ErrReadLimitTooLarge
		}
		if cfg.readLimit == 0 {
			return ErrReadLimitZero
		}
	}

	l, err := ParseURL(url)
	if err != nil {
		return err
	}

	if cfg.hasReadLimit && !l.hasMirror() {
		return ErrReadLimitNeedsMirror
	}

	var readLimit *uint32
	if cfg.hasReadLimit {
		readLimit = &cfg.readLimit
	}

	if _, err := cp.sendFull(0x5F, []byte{cp.ndefFileNumber}, fileSettings(l, sdmKeyNo, readLimit)); err != nil {
		return err
	}

	b, err := ndef.NewURIMessage(l.URL).Marshal()
	if err != nil {
		return err
	}

	return cp.writeNDEF(b)
}
