package commands

import "github.com/jphastings/ntag424/types"

type CommandProcessor struct {
	card types.Card

	ndefFileID     []byte
	ndefFileNumber uint
}

func NewCommandProcessor(card types.Card) CommandProcessor {
	c := CommandProcessor{
		card: card,
	}

	// TODO: Read CC file
	// c.ISOSelectFile()

	c.ndefFileNumber = 2
	c.ndefFileID = []byte{0xE1, 0x04}

	return c
}
