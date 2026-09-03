package commands

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/hsanjuan/go-ndef"
)

var aidNDEF = []byte{0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01}

// ErrNDEFTooLong is returned when an NDEF message doesn't fit in the tag's 256-byte NDEF file.
var ErrNDEFTooLong = errors.New("NDEF message too long for the tag's 256 byte NDEF file")

// ReadNDEF reads and parses the NDEF message currently stored on the tag.
func (cp *CommandProcessor) ReadNDEF() (*ndef.Message, error) {
	if err := cp.ISOSelectFile(SelectDirectoryByName(aidNDEF)); err != nil {
		return nil, err
	}

	if err := cp.ISOSelectFile(SelectAnyByIdentifier(cp.ndefFileID)); err != nil {
		return nil, err
	}

	b, err := cp.ISOReadBinary(2, 0)
	if err != nil {
		return nil, err
	}

	ndefLen := int(binary.BigEndian.Uint16(b))
	b, err = cp.ISOReadBinary(ndefLen, 2)
	if err != nil {
		return nil, err
	}

	msg := &ndef.Message{}
	l, err := msg.Unmarshal(b)
	if err != nil {
		return nil, err
	}
	if l != int(ndefLen) {
		return nil, fmt.Errorf("could only parse %d of %d NDEF bytes", l, ndefLen)
	}

	return msg, nil
}

// WriteNDEF marshals msg and writes it to the tag's NDEF file, in plain mode.
func (cp *CommandProcessor) WriteNDEF(msg *ndef.Message) error {
	b, err := msg.Marshal()
	if err != nil {
		return err
	}

	return cp.writeNDEF(b)
}

func (cp *CommandProcessor) writeNDEF(b []byte) error {
	if 2+len(b) > 256 {
		return ErrNDEFTooLong
	}

	if err := cp.ISOSelectFile(SelectDirectoryByName(aidNDEF)); err != nil {
		return err
	}

	if err := cp.ISOSelectFile(SelectAnyByIdentifier(cp.ndefFileID)); err != nil {
		return err
	}

	lenB := make([]byte, 2)
	binary.BigEndian.PutUint16(lenB, uint16(len(b)))
	if err := cp.ISOUpdateBinary(lenB, 0); err != nil {
		return err
	}

	return cp.ISOUpdateBinary(b, 2)
}
