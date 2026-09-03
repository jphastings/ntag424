package cards

import (
	"errors"
)

type apduError struct {
	context string
	sub     map[byte]error
}

var apduErrors = map[byte]apduError{
	0x64: {
		context: "State of non-volatile memory unchanged",
		sub: map[byte]error{
			0x00: errors.New("no information given (NV-Ram not changed)"),
			0x01: errors.New("command timeout. Immediate response required by the card"),
		},
	},
	0x65: {
		context: "State of non-volatile memory changed",
		sub: map[byte]error{
			0x00: errors.New("no information given"),
			0x01: errors.New("write error. Memory failure. There have been problems in writing or reading the EEPROM. Other hardware problems may also bring this error"),
			0x81: errors.New("memory failure"),
		},
	},
	0x67: {
		sub: map[byte]error{
			0x00: errors.New("wrong length"),
		},
	},
	0x69: {
		context: "Command not allowed",
		sub: map[byte]error{
			0x00: errors.New("no information given"),
			0x81: errors.New("command incompatible with file structure"),
			0x82: errors.New("security status not satisfied"),
			0x83: errors.New("authentication method blocked"),
			0x84: errors.New("referenced data invalidated"),
			0x85: errors.New("conditions of use not satisfied"),
			0x86: errors.New("command not allowed (no current EF)"),
			0x87: errors.New("expected secure messaging data objects missing"),
			0x88: errors.New("incorrect secure messaging data objects"),
		},
	},
	0x6A: {
		context: "Wrong parameter(s) P1-P2",
		sub: map[byte]error{
			0x00: errors.New("no information given (Bytes P1 and/or P2 are incorrect)"),
			0x80: errors.New("the parameters in the data field are incorrect"),
			0x81: errors.New("function not supported"),
			0x82: errors.New("file not found"),
			0x83: errors.New("record not found"),
			0x84: errors.New("there is insufficient memory space in record or file"),
			0x85: errors.New("lc inconsistent with TLV structure"),
			0x86: errors.New("incorrect P1 or P2 parameter"),
			0x87: errors.New("lc inconsistent with P1-P2"),
			0x88: errors.New("referenced data not found"),
			0x89: errors.New("file already exists"),
			0x8A: errors.New("dF name already exists"),
			0xF0: errors.New("wrong parameter value"),
		},
	},
	0x6C: {
		context: "Wrong length Le",
		sub: map[byte]error{
			0x00: errors.New("incorrect P3 length"),
		},
	},
	0x91: {
		context: "OK (?)",
		sub: map[byte]error{
			0x01: errors.New("states.activity, States.lock Status or States.lockable has wrong value"),
			0x02: errors.New("transaction number reached its limit"),
			0x0C: errors.New("no changes"),
			0x0E: errors.New("insufficient NV-Memory to complete command"),
			0x1C: errors.New("command code not supported"),
			0x1E: errors.New("the CRC or MAC does not match data"),
			0x40: errors.New("invalid key number specified"),
			0x7E: errors.New("length of command string invalid"),
			0x9D: errors.New("not allow the requested command"),
			0x9E: errors.New("value of the parameter invalid"),
			0xA0: errors.New("requested AID not present on PICC"),
			0xA1: errors.New("unrecoverable error within application"),
			0xAE: errors.New("authentication status does not allow the requested command"),
			0xAF: errors.New("additional data frame is expected to be sent"),
			0xBE: errors.New("out of boundary"),
			0xC1: errors.New("unrecoverable error within PICC"),
			0xCA: errors.New("previous Command was not fully completed"),
			0xCD: errors.New("the PICC was disabled by an unrecoverable error"),
			0xCE: errors.New("number of Applications limited to 28"),
			0xDE: errors.New("file or application already exists"),
			0xEE: errors.New("could not complete NV-write operation due to loss of power"),
			0xF0: errors.New("specified file number does not exist"),
			0xF1: errors.New("unrecoverable error within file"),
		},
	},
}
