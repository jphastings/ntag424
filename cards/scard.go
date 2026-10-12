package cards

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jphastings/ntag424/types"
	"github.com/skythen/apdu"
	"github.com/telesma-app/pcsc"
)

var (
	// ErrUnknownReader is returned when WaitForCard is given a reader name
	// that isn't attached.
	ErrUnknownReader = pcsc.ErrUnknownReader
	// ErrNoReaders is returned when a card is wanted from the first reader but
	// none is attached.
	ErrNoReaders = pcsc.ErrNoReaders
)

// Scard is a connection to a smart card through a PC/SC reader.
type Scard struct {
	card *pcsc.Card
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
	readers, err := readerStates()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, r := range readers {
		names = append(names, r.Name)
	}
	return names, nil
}

func readerStates() ([]*pcsc.ReaderInfo, error) {
	var readers []*pcsc.ReaderInfo
	for r, err := range pcsc.Enumerate() {
		if err != nil {
			return nil, unavailableHint(err)
		}
		readers = append(readers, r)
	}
	return readers, nil
}

// unavailableHint says what to install when the PC/SC library or service is
// missing, which only happens on Linux: macOS and Windows ship both.
func unavailableHint(err error) error {
	if errors.Is(err, pcsc.ErrUnavailable) || errors.Is(err, pcsc.ErrNoService) {
		return fmt.Errorf("%w (install and start pcscd and libpcsclite, eg. `apt install pcscd libpcsclite1`)", err)
	}
	return err
}

func connect(ctx context.Context, reader string, wait bool) (*Scard, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if reader == "" {
		readers, err := Readers()
		if err != nil {
			return nil, err
		}
		if len(readers) == 0 {
			return nil, ErrNoReaders
		}
		reader = readers[0]
	}

	if wait {
		if err := waitForPresence(ctx, reader); err != nil {
			return nil, err
		}
	}

	card, err := pcsc.Open(reader, pcsc.WithShareMode(pcsc.ShareModeExclusive))
	if err != nil {
		return nil, unavailableHint(err)
	}
	return &Scard{card: card}, nil
}

// presencePoll is how often WaitForCard looks for a card. Polling keeps the
// wait simple and cancellable without relying on SCardCancel, which not every
// PC/SC implementation honours.
const presencePoll = 250 * time.Millisecond

func waitForPresence(ctx context.Context, reader string) error {
	tick := time.NewTicker(presencePoll)
	defer tick.Stop()

	for {
		readers, err := readerStates()
		if err != nil {
			return err
		}

		found := false
		for _, r := range readers {
			if r.Name != reader {
				continue
			}
			if r.State&pcsc.ReaderStatePresent != 0 {
				return nil
			}
			found = true
		}
		if !found {
			return fmt.Errorf("%w: %q", ErrUnknownReader, reader)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
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
	if c.card == nil {
		return nil
	}
	// pcsc.Open's default leaves the card powered and untouched, because
	// closing a connection should not reset a tag mid-use.
	err := c.card.Close()
	c.card = nil
	return err
}

func (c *Scard) SendCommandAPDU(cmd *apdu.Capdu) (*apdu.Rapdu, error) {
	if c.card == nil {
		return nil, errors.New("card connection is closed")
	}

	b, err := cmd.Bytes()
	if err != nil {
		return nil, fmt.Errorf("couldn't encode APDU command: %w", err)
	}

	res, err := c.card.Transmit(context.Background(), b)
	if err != nil {
		return nil, fmt.Errorf("couldn't transmit to card: %w", err)
	}

	r, err := apdu.ParseRapdu(res)
	if err != nil {
		return nil, fmt.Errorf("couldn't interpret APDU response: %w", err)
	}

	if err := statusError(r); err != nil {
		return nil, err
	}

	return r, nil
}

// statusError returns a *types.StatusError describing r's status word, or
// nil if it reports success.
func statusError(r *apdu.Rapdu) error {
	if isSuccess(r) {
		return nil
	}

	e := &types.StatusError{SW: uint16(r.SW1)<<8 | uint16(r.SW2)}
	if ae, ok := apduErrors[r.SW1]; ok {
		e.Reason = ae.context
		if sub, ok := ae.sub[r.SW2]; ok {
			e.Reason = sub
			if ae.context != "" {
				e.Reason = ae.context + ": " + sub
			}
		}
	}
	return e
}

// isSuccess reports true for 0x9000, plus 0x9100 and 0x91AF: NTAG 424 native
// commands use these to signal success and "additional frame expected".
func isSuccess(r *apdu.Rapdu) bool {
	return r.IsSuccess() || (r.SW1 == 0x91 && (r.SW2 == 0x00 || r.SW2 == 0xAF))
}
