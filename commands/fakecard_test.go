package commands

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jphastings/ntag424/types"
	"github.com/skythen/apdu"
	"github.com/stretchr/testify/require"
)

// exchange describes one expected C-APDU/R-APDU round trip for fakeCard.
// If capdu is empty, only the Ins byte of the sent Capdu is checked.
type exchange struct {
	capdu string
	ins   byte
	rapdu string
}

type fakeCard struct {
	t         *testing.T
	exchanges []exchange
	i         int
	sent      [][]byte // raw C-APDU bytes seen by each call, in order
}

func newFakeCard(t *testing.T, exchanges ...exchange) *fakeCard {
	return &fakeCard{t: t, exchanges: exchanges}
}

func (f *fakeCard) SendCommandAPDU(cmd *apdu.Capdu) (*apdu.Rapdu, error) {
	f.t.Helper()
	require.Less(f.t, f.i, len(f.exchanges), "unexpected extra APDU sent")
	ex := f.exchanges[f.i]
	f.i++

	b, err := cmd.Bytes()
	require.NoError(f.t, err)
	f.sent = append(f.sent, b)

	if ex.capdu != "" {
		require.Equal(f.t, ex.capdu, strings.ToUpper(hex.EncodeToString(b)))
	} else {
		require.Equal(f.t, ex.ins, cmd.Ins, "unexpected INS")
	}

	reply, err := hex.DecodeString(ex.rapdu)
	require.NoError(f.t, err)
	r, err := apdu.ParseRapdu(reply)
	require.NoError(f.t, err)

	// Like a real reader, report failing status words as errors.
	if !r.IsSuccess() && !(r.SW1 == 0x91 && (r.SW2 == 0x00 || r.SW2 == 0xAF)) {
		return nil, &types.StatusError{SW: uint16(r.SW1)<<8 | uint16(r.SW2)}
	}
	return r, nil
}
