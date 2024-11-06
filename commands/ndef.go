package commands

import (
	"encoding/binary"
	"fmt"

	"github.com/hsanjuan/go-ndef"
)

var (
	aid = []byte{0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01}
)

func (cp CommandProcessor) ReadNDEF() (*ndef.Message, error) {
	if err := cp.ISOSelectFile(SelectDirectoryByName(aid)); err != nil {
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

func (cp CommandProcessor) WriteNDEF(*ndef.Message) error {
	return fmt.Errorf("writing NDEF not yet implemented")
}
