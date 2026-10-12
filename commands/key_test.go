package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// table26Session returns the AN12196 Tables 26/27 session, keyed on key 0, at ctr.
func table26Session(t *testing.T, ctr uint16) *session {
	t.Helper()
	return &session{
		encKey: mustHex(t, "4CF3CB41A22583A61E89B158D252FC53"),
		macKey: mustHex(t, "5529860B2FC5FB6154B7F28361D30BF9"),
		ti:     mustHex(t, "7614281A"),
		ctr:    ctr,
		keyNo:  0,
	}
}

func TestChangeKey_OtherKey(t *testing.T) {
	fake := newFakeCard(t,
		exchange{capdu: "90C4000029022CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9E16C2393AE9CD1FAC75D0CE20BCD1D06E600", rapdu: "203BB55D1089D5879100"},
	)

	cp := NewCommandProcessor(fake)
	cp.session = table26Session(t, 2)

	err := cp.ChangeKey(2, make([]byte, 16), mustHex(t, "F3847D627727ED3BC9C4CC050489B966"), 0x01)
	require.NoError(t, err)

	require.NotNil(t, cp.session)
	assert.Equal(t, uint16(3), cp.session.ctr)
}

func TestChangeKey_OwnKey(t *testing.T) {
	fake := newFakeCard(t,
		exchange{capdu: "90C400002900C0EB4DEEFEDDF0B513A03A95A75491818580503190D4D05053FF75668A01D6FDA6610234BDED643200", rapdu: "9100"},
	)

	cp := NewCommandProcessor(fake)
	cp.session = table26Session(t, 3)

	err := cp.ChangeKey(0, nil, mustHex(t, "5004BF991F408672B1EF00F08F9E8647"), 0x01)
	require.NoError(t, err)

	assert.Nil(t, cp.session)
}

func TestChangeKey_InvalidKeyNo(t *testing.T) {
	cp := NewCommandProcessor(newFakeCard(t))
	cp.session = table26Session(t, 0)

	err := cp.ChangeKey(5, make([]byte, 16), make([]byte, 16), 0x01)
	assert.ErrorIs(t, err, ErrInvalidKeyNo)
}

func TestChangeKey_RequiresAuthentication(t *testing.T) {
	cp := NewCommandProcessor(newFakeCard(t))

	err := cp.ChangeKey(1, make([]byte, 16), make([]byte, 16), 0x01)
	assert.ErrorIs(t, err, ErrNotAuthenticated)
}

func TestChangeKey_InvalidNewKeyLength(t *testing.T) {
	cp := NewCommandProcessor(newFakeCard(t))
	cp.session = table26Session(t, 0)

	err := cp.ChangeKey(1, make([]byte, 16), make([]byte, 15), 0x01)
	assert.Error(t, err)
}

func TestChangeKey_OldKeyRequiredForOtherKey(t *testing.T) {
	cp := NewCommandProcessor(newFakeCard(t))
	cp.session = table26Session(t, 0)

	err := cp.ChangeKey(1, nil, make([]byte, 16), 0x01)
	assert.ErrorIs(t, err, ErrOldKeyRequired)
}

func TestChangeKeyCRC(t *testing.T) {
	assert.Equal(t, "789DFADC", upperHex(changeKeyCRC(mustHex(t, "F3847D627727ED3BC9C4CC050489B966"))))
}

func TestKeyVersion(t *testing.T) {
	fake := newFakeCard(t,
		exchange{capdu: "00A4040C07D2760000850101", rapdu: "9000"},
		exchange{capdu: "90640000010300", rapdu: "019100"},
	)

	v, err := NewCommandProcessor(fake).KeyVersion(3)
	require.NoError(t, err)
	assert.Equal(t, byte(1), v)
}

func TestKeyVersion_InvalidKeyNo(t *testing.T) {
	_, err := NewCommandProcessor(newFakeCard(t)).KeyVersion(5)
	assert.ErrorIs(t, err, ErrInvalidKeyNo)
}
