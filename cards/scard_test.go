package cards

import (
	"testing"

	"github.com/jphastings/ntag424/types"
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
