package types

import (
	"fmt"

	"github.com/skythen/apdu"
)

// Card sends command APDUs to a card. When the card answers with a status
// word reporting failure, implementations return a *StatusError.
type Card interface {
	SendCommandAPDU(*apdu.Capdu) (*apdu.Rapdu, error)
}

// StatusError is a card's refusal of a command, identified by the status
// word it answered with, such as 0x91AE.
type StatusError struct {
	SW     uint16
	Reason string // what the status word means, if known
}

func (e *StatusError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("card returned status %04X", e.SW)
	}
	return fmt.Sprintf("%s (status %04X)", e.Reason, e.SW)
}
