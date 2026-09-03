package cards

import (
	"errors"
	"fmt"

	"github.com/ebfe/scard"
	"github.com/skythen/apdu"
)

// Scard is a connection to a smart card through a PC/SC reader.
type Scard struct {
	ctx  *scard.Context
	card *scard.Card
}

func NewScard() (*Scard, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, err
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		ctx.Release()
		return nil, err
	}

	if len(readers) == 0 {
		ctx.Release()
		return nil, scard.ErrNoReadersAvailable
	}

	// TODO: Connect to non-first reader?
	card, err := ctx.Connect(readers[0], scard.ShareExclusive, scard.ProtocolAny)
	if err != nil {
		ctx.Release()
		return nil, err
	}

	return &Scard{ctx: ctx, card: card}, nil
}

// Close disconnects from the card and releases the reader. Safe to call more
// than once.
func (c *Scard) Close() error {
	var errs []error

	if c.card != nil {
		// The card is left powered and untouched, because closing a connection
		// should not reset a tag mid-use.
		errs = append(errs, c.card.Disconnect(scard.LeaveCard))
		c.card = nil
	}
	if c.ctx != nil {
		errs = append(errs, c.ctx.Release())
		c.ctx = nil
	}

	return errors.Join(errs...)
}

func (c *Scard) SendCommandAPDU(cmd *apdu.Capdu) (*apdu.Rapdu, error) {
	if c.card == nil {
		return nil, errors.New("card connection is closed")
	}

	b, err := cmd.Bytes()
	if err != nil {
		return nil, fmt.Errorf("couldn't encode APDU command: %w", err)
	}

	res, err := c.card.Transmit(b)
	if err != nil {
		return nil, fmt.Errorf("couldn't transmit to card: %w", err)
	}

	r, err := apdu.ParseRapdu(res)
	if err != nil {
		return nil, fmt.Errorf("couldn't interpret APDU response: %w", err)
	}

	if !isSuccess(r) {
		ae, ok := apduErrors[r.SW1]
		if !ok {
			return nil, fmt.Errorf("unknown APDU error %02X%02X", r.SW1, r.SW2)
		}
		err, ok := ae.sub[r.SW2]
		if !ok {
			return nil, fmt.Errorf("unknown APDU error %02X%02X (%s)", r.SW1, r.SW2, ae.context)
		}
		if ae.context != "" {
			return nil, fmt.Errorf("%s: %w", ae.context, err)
		}
		return nil, err
	}

	return r, nil
}

// isSuccess reports true for 0x9000, plus 0x9100 and 0x91AF: NTAG 424 native
// commands use these to signal success and "additional frame expected".
func isSuccess(r *apdu.Rapdu) bool {
	return r.IsSuccess() || (r.SW1 == 0x91 && (r.SW2 == 0x00 || r.SW2 == 0xAF))
}
