package commands

import (
	"crypto/rand"
	"io"

	"github.com/jphastings/ntag424/types"
)

// CommandProcessor sends NTAG 424 DNA commands to a Card, tracking the secure
// messaging session established by Authenticate.
type CommandProcessor struct {
	card types.Card

	rand    io.Reader
	session *session

	ndefFileID     []byte
	ndefFileNumber byte
}

// NewCommandProcessor returns a CommandProcessor that issues commands to card.
func NewCommandProcessor(card types.Card) *CommandProcessor {
	return &CommandProcessor{
		card:           card,
		rand:           rand.Reader,
		ndefFileID:     []byte{0xE1, 0x04},
		ndefFileNumber: 2,
	}
}
