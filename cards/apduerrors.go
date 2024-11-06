package cards

import "errors"

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
}
