package cards

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/jphastings/ntag424/types"
	"github.com/skythen/apdu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ types.Card = (*Scard)(nil)

func TestScardClose_Idempotent(t *testing.T) {
	c := &Scard{}

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: got %v, want nil", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: got %v, want nil", err)
	}
}

func TestScardSendCommandAPDU_AfterClose(t *testing.T) {
	c := &Scard{}

	if _, err := c.SendCommandAPDU(nil); err == nil {
		t.Fatal("SendCommandAPDU on a closed Scard: got nil error, want an error")
	}
}

func TestStatusError(t *testing.T) {
	cases := []struct {
		rapdu string
		want  string // empty for success
	}{
		{"9000", ""},
		{"9100", ""},
		{"91AF", ""},
		{"91AE", "NTAG 424 native command failed: authentication status does not allow the requested command (status 91AE)"},
		{"6982", "Command not allowed: security status not satisfied (status 6982)"},
		{"6F00", "card returned status 6F00"},
	}

	for _, c := range cases {
		b, _ := hex.DecodeString(c.rapdu)
		r, err := apdu.ParseRapdu(b)
		require.NoError(t, err)

		err = statusError(r)
		if c.want == "" {
			assert.NoError(t, err, c.rapdu)
			continue
		}
		var se *types.StatusError
		require.ErrorAs(t, err, &se, c.rapdu)
		assert.Equal(t, c.want, se.Error())
	}
}

func TestWaitForCard_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := WaitForCard(ctx, "")
	assert.ErrorIs(t, err, context.Canceled)
}
