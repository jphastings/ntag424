package cards

import (
	"fmt"

	"github.com/ebfe/scard"
	"github.com/jphastings/ntag424/types"
	"github.com/skythen/apdu"
)

type scardCard struct {
	scard *scard.Card
}

func NewScard() (types.Card, error) {
	sctx, err := scard.EstablishContext()
	if err != nil {
		return nil, err
	}

	readers, err := sctx.ListReaders()
	if err != nil {
		return nil, err
	}

	if len(readers) == 0 {
		return nil, scard.ErrNoReadersAvailable
	}

	// TODO: Connect to non-first reader?
	card, err := sctx.Connect(readers[0], scard.ShareExclusive, scard.ProtocolAny)
	if err != nil {
		return nil, err
	}

	return scardCard{scard: card}, nil
}

func (c scardCard) SendCommand(cmd *apdu.Capdu) (*apdu.Rapdu, error) {
	b, err := cmd.Bytes()
	if err != nil {
		return nil, fmt.Errorf("couldn't encode APDU command: %w", err)
	}

	res, err := c.scard.Transmit(b)
	if err != nil {
		return nil, fmt.Errorf("couldn't transmit to card: %w", err)
	}

	r, err := apdu.ParseRapdu(res)
	if err != nil {
		return nil, fmt.Errorf("couldn't interpret APDU response: %w", err)
	}

	if r.IsError() {
		ae, ok := apduErrors[r.SW1]
		if !ok {
			return nil, fmt.Errorf("unknown APDU error type %x", r.SW1)
		}
		err, ok := ae.sub[r.SW2]
		if !ok {
			return nil, fmt.Errorf("unknown APDU error %x (%s)", r.SW1, ae.context)
		}
		return nil, err
	}

	return r, nil
}
