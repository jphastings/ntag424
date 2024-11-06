package commands

import "github.com/jphastings/ntag424/types"

type CommandProcessor struct {
	card types.Card

	ndefFileID []byte
}

func NewCommandProcessor(card types.Card) CommandProcessor {
	c := CommandProcessor{
		card: card,
	}

	// Read CC file
	// c.ISOSelectFile()

	c.ndefFileID = []byte{0xE1, 0x04}

	return c
}
