package commands

import (
	"encoding/binary"
	"errors"

	"github.com/skythen/apdu"
)

var (
	ErrBinaryTooLong = errors.New("provided binary is longer than can be written in one go")
	ErrOffsetInvalid = errors.New("offset cannot be bigger 32,767 bytes")
)

func binaryOffset(n uint16) ([]byte, error) {
	if n > 32767 {
		return nil, ErrOffsetInvalid
	}
	off := make([]byte, 2)
	binary.BigEndian.PutUint16(off, n)

	return off, nil
}

// Reads the binary information in the *currently selected file* from the provided offset.
func (cp CommandProcessor) ISOReadBinary(len int, offset uint16) ([]byte, error) {
	off, err := binaryOffset(offset)
	if err != nil {
		return nil, err
	}

	r, err := cp.card.SendCommandAPDU(&apdu.Capdu{
		Cla: 0x00, Ins: 0xB0, P1: off[0], P2: off[1],
		Ne: len,
	})
	if err != nil {
		return nil, err
	}
	return r.Data, nil
}

// Updates the binary information in the *currently selected file* at the provided offset.
func (cp CommandProcessor) ISOUpdateBinary(data []byte, offset uint16) error {
	if len(data) > 255 {
		return ErrBinaryTooLong
	}
	off, err := binaryOffset(offset)
	if err != nil {
		return err
	}

	_, err = cp.card.SendCommandAPDU(&apdu.Capdu{
		Cla: 0x00, Ins: 0xD6, P1: off[0], P2: off[1],
		Data: data,
	})
	return err
}

type selectInstruction struct {
	p1   byte
	data []byte
}

var (
	// Selects the root PICC level file
	SelectPICCLevel = selectInstruction{p1: 0x00, data: []byte{}}

	// Selects the parent directory file
	SelectParentDirectory = selectInstruction{p1: 0x03, data: []byte{}}

	// Selects any file type by its identifier
	SelectAnyByIdentifier = func(id []byte) selectInstruction {
		return selectInstruction{p1: 0x00, data: id}
	}

	// Selects the directory with the given identifier if it exists within the current directory
	SelectChildDirectory = func(id []byte) selectInstruction {
		return selectInstruction{p1: 0x01, data: id}
	}

	// Selects an elementary file, *within* the current directory file, by its identifier
	SelectElementaryFile = func(id []byte) selectInstruction {
		return selectInstruction{p1: 0x02, data: id}
	}
	// Selects the directory file with the given name
	SelectDirectoryByName = func(name []byte) selectInstruction {
		return selectInstruction{p1: 0x04, data: name}
	}
)

const selectNoResponseData = 0x0C

func (cp CommandProcessor) ISOSelectFile(s selectInstruction) error {
	_, err := cp.card.SendCommandAPDU(&apdu.Capdu{
		Cla: 0x00, Ins: 0xA4, P1: s.p1, P2: selectNoResponseData,
		Data: s.data,
	})
	return err
}
