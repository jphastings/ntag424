package cards

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ebfe/scard"
	"github.com/skythen/apdu"
)

// Scard is a connection to a smart card through a PC/SC reader.
type Scard struct {
	ctx  *scard.Context
	card *scard.Card
}

// NewScard connects to the card on the first reader attached. It fails if
// no card is present: use WaitForCard to wait for one.
func NewScard() (*Scard, error) {
	return connect(context.Background(), "", false)
}

// WaitForCard waits for a card to be presented to the named reader, then
// connects to it. A card already on the reader is used straight away. An
// empty name means the first reader attached. Cancelling ctx abandons the
// wait.
func WaitForCard(ctx context.Context, reader string) (*Scard, error) {
	return connect(ctx, reader, true)
}

// Readers lists the names of the PC/SC readers attached, for WaitForCard.
func Readers() ([]string, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, err
	}
	defer ctx.Release()

	readers, err := ctx.ListReaders()
	if errors.Is(err, scard.ErrNoReadersAvailable) {
		return nil, nil
	}
	return readers, err
}

func connect(ctx context.Context, reader string, wait bool) (*Scard, error) {
	sctx, err := scard.EstablishContext()
	if err != nil {
		return nil, err
	}

	card, err := connectCard(ctx, sctx, reader, wait)
	if err != nil {
		sctx.Release()
		return nil, err
	}

	return &Scard{ctx: sctx, card: card}, nil
}

func connectCard(ctx context.Context, sctx *scard.Context, reader string, wait bool) (*scard.Card, error) {
	if reader == "" {
		readers, err := sctx.ListReaders()
		if err != nil {
			return nil, err
		}
		if len(readers) == 0 {
			return nil, scard.ErrNoReadersAvailable
		}
		reader = readers[0]
	}

	if wait {
		if err := waitForPresence(ctx, sctx, reader); err != nil {
			return nil, err
		}
	}

	return sctx.Connect(reader, scard.ShareExclusive, scard.ProtocolAny)
}

// presencePoll bounds each GetStatusChange call so a cancelled context is
// noticed promptly. Polling avoids relying on SCardCancel from another
// goroutine, which not every PC/SC implementation honours.
const presencePoll = 250 * time.Millisecond

func waitForPresence(ctx context.Context, sctx *scard.Context, reader string) error {
	states := []scard.ReaderState{{Reader: reader, CurrentState: scard.StateUnaware}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := sctx.GetStatusChange(states, presencePoll)
		if errors.Is(err, scard.ErrTimeout) {
			continue
		}
		if err != nil {
			return err
		}

		if states[0].EventState&scard.StatePresent != 0 {
			return nil
		}
		states[0].CurrentState = states[0].EventState
	}
}

// UID reads the tag's 7-byte serial number from the reader. It needs no keys
// and no application selected, as the reader answers from what it saw when
// the card arrived.
func (c *Scard) UID() ([]byte, error) {
	// PC/SC part 3's GET DATA pseudo-APDU, handled by the reader itself.
	r, err := c.SendCommandAPDU(&apdu.Capdu{Cla: 0xFF, Ins: 0xCA, P1: 0x00, P2: 0x00, Ne: apdu.MaxLenResponseDataStandard})
	if err != nil {
		return nil, fmt.Errorf("couldn't read UID: %w", err)
	}
	return r.Data, nil
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
