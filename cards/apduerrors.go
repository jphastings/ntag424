package cards

type apduError struct {
	context string
	sub     map[byte]string
}

var apduErrors = map[byte]apduError{
	0x64: {
		context: "State of non-volatile memory unchanged",
		sub: map[byte]string{
			0x00: "no information given (NV-Ram not changed)",
			0x01: "command timeout. Immediate response required by the card",
		},
	},
	0x65: {
		context: "State of non-volatile memory changed",
		sub: map[byte]string{
			0x00: "no information given",
			0x01: "write error. Memory failure. There have been problems in writing or reading the EEPROM. Other hardware problems may also bring this error",
			0x81: "memory failure",
		},
	},
	0x67: {
		sub: map[byte]string{
			0x00: "wrong length",
		},
	},
	0x69: {
		context: "Command not allowed",
		sub: map[byte]string{
			0x00: "no information given",
			0x81: "command incompatible with file structure",
			0x82: "security status not satisfied",
			0x83: "authentication method blocked",
			0x84: "referenced data invalidated",
			0x85: "conditions of use not satisfied",
			0x86: "command not allowed (no current EF)",
			0x87: "expected secure messaging data objects missing",
			0x88: "incorrect secure messaging data objects",
		},
	},
	0x6A: {
		context: "Wrong parameter(s) P1-P2",
		sub: map[byte]string{
			0x00: "no information given (Bytes P1 and/or P2 are incorrect)",
			0x80: "the parameters in the data field are incorrect",
			0x81: "function not supported",
			0x82: "file not found",
			0x83: "record not found",
			0x84: "there is insufficient memory space in record or file",
			0x85: "lc inconsistent with TLV structure",
			0x86: "incorrect P1 or P2 parameter",
			0x87: "lc inconsistent with P1-P2",
			0x88: "referenced data not found",
			0x89: "file already exists",
			0x8A: "dF name already exists",
			0xF0: "wrong parameter value",
		},
	},
	0x6C: {
		context: "Wrong length Le",
		sub: map[byte]string{
			0x00: "incorrect P3 length",
		},
	},
	0x91: {
		context: "NTAG 424 native command failed",
		sub: map[byte]string{
			0x01: "states.activity, States.lock Status or States.lockable has wrong value",
			0x02: "transaction number reached its limit",
			0x0C: "no changes",
			0x0E: "insufficient NV-Memory to complete command",
			0x1C: "command code not supported",
			0x1E: "the CRC or MAC does not match data",
			0x40: "invalid key number specified",
			0x7E: "length of command string invalid",
			0x9D: "not allow the requested command",
			0x9E: "value of the parameter invalid",
			0xA0: "requested AID not present on PICC",
			0xA1: "unrecoverable error within application",
			0xAE: "authentication status does not allow the requested command",
			0xAF: "additional data frame is expected to be sent",
			0xBE: "out of boundary",
			0xC1: "unrecoverable error within PICC",
			0xCA: "previous Command was not fully completed",
			0xCD: "the PICC was disabled by an unrecoverable error",
			0xCE: "number of Applications limited to 28",
			0xDE: "file or application already exists",
			0xEE: "could not complete NV-write operation due to loss of power",
			0xF0: "specified file number does not exist",
			0xF1: "unrecoverable error within file",
		},
	},
}
