package commands

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/skythen/apdu"
)

var (
	sdmOptsUID     uint16 = 0b10000000
	sdmOptsCounter uint16 = 0b01000000
	sdmOptsASCII   uint16 = 0b00000001

	fileOptsEnableSDM uint16 = 0b01000000
	fileOptsModePlain uint16 = 0b00
	fileOptsModeMAC   uint16 = 0b01
	fileOptsModeFull  uint16 = 0b11
)

type mirrorConfig struct {
	enabled    bool
	uidPos     int
	counterPos int
	sdmOpts    uint16
}

var (
	// These are all the same length as the data that will be inserted over the top of them by SDM
	MirrorUID     = "{{uid}}"
	MirrorCounter = "{c}"
)

func getMirrorConfig(data []byte) mirrorConfig {
	uidPos := bytes.Index(data, []byte(MirrorUID))
	counterPos := bytes.Index(data, []byte(MirrorCounter))

	sdmOpts := sdmOptsASCII

	if uidPos != -1 {
		sdmOpts = sdmOpts | sdmOptsUID
	}
	if counterPos != -1 {
		sdmOpts = sdmOpts | sdmOptsCounter
	}

	return mirrorConfig{
		enabled:    uidPos != -1 || counterPos != -1,
		uidPos:     uidPos,
		counterPos: counterPos,
		sdmOpts:    sdmOpts,
	}
}

func (cp CommandProcessor) EnableSDM(m mirrorConfig) error {
	data := []byte{}

	// Configure SDM use for NDEF file
	header := byte(cp.ndefFileNumber)
	data = append(data, header)

	// File options
	data = append(data, byte(fileOptsModePlain|fileOptsEnableSDM))

	// TODO: Access Permissions (page 64)
	data = append(data, []byte{0x00, 0xE0}...)

	// SDM Options
	data = append(data, byte(m.sdmOpts))

	// TODO: SDMAccessRights (Page 65)
	data = append(data, []byte{0xFF, 0xFE}...)

	if m.uidPos != -1 {
		bPos := make([]byte, 4)
		binary.LittleEndian.PutUint32(bPos, uint32(m.uidPos))
		data = append(data, bPos[:3]...)
	}

	if m.counterPos != -1 {
		bPos := make([]byte, 4)
		binary.LittleEndian.PutUint32(bPos, uint32(m.counterPos))
		data = append(data, bPos[:3]...)
	}

	cmd := &apdu.Capdu{
		// ChangeFileSettings command
		Cla: 0x90, Ins: 0x5F, P1: 0x00, P2: 0x00,
		Data: data,
	}

	b, _ := cmd.Bytes()
	fmt.Printf("%X\n", b)

	_, err := cp.card.SendCommandAPDU(cmd)

	return err
}
