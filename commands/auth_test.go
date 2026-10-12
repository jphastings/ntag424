package commands

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func upperHex(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

func table14Session(t *testing.T) *CommandProcessor {
	t.Helper()
	fake := newFakeCard(t,
		exchange{capdu: "00A4040C07D2760000850101", rapdu: "9000"},
		exchange{capdu: "9071000002000000", rapdu: "A04C124213C186F22399D33AC2A3021591AF"},
		exchange{capdu: "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00", rapdu: "3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F081206639100"},
	)

	cp := NewCommandProcessor(fake)
	cp.rand = bytes.NewReader(mustHex(t, "13C5DB8A5930439FC3DEF9A4C675360F"))
	return cp
}

func TestAuthenticate(t *testing.T) {
	cp := table14Session(t)

	err := cp.Authenticate(0, make([]byte, 16))
	require.NoError(t, err)

	require.NotNil(t, cp.session)
	assert.Equal(t, "9D00C4DF", upperHex(cp.session.ti))
	assert.Equal(t, "1309C877509E5A215007FF0ED19CA564", upperHex(cp.session.encKey))
	assert.Equal(t, "4C6626F5E72EA694202139295C7A7FC7", upperHex(cp.session.macKey))
	assert.Equal(t, uint16(0), cp.session.ctr)
	assert.Equal(t, byte(0), cp.session.keyNo)
}

func TestAuthenticate_TamperedResponseFails(t *testing.T) {
	fake := newFakeCard(t,
		exchange{capdu: "00A4040C07D2760000850101", rapdu: "9000"},
		exchange{capdu: "9071000002000000", rapdu: "A04C124213C186F22399D33AC2A3021591AF"},
		// Last data byte of the (otherwise correct) reply flipped; SW left at 9100.
		exchange{capdu: "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00", rapdu: "3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F081206629100"},
	)

	cp := NewCommandProcessor(fake)
	cp.rand = bytes.NewReader(mustHex(t, "13C5DB8A5930439FC3DEF9A4C675360F"))

	err := cp.Authenticate(0, make([]byte, 16))
	assert.ErrorIs(t, err, ErrAuthFailed)
}

func TestAuthenticate_WrongKey(t *testing.T) {
	fake := newFakeCard(t,
		exchange{capdu: "00A4040C07D2760000850101", rapdu: "9000"},
		exchange{capdu: "9071000002000000", rapdu: "A04C124213C186F22399D33AC2A3021591AF"},
		exchange{ins: 0xAF, rapdu: "91AE"},
	)

	err := NewCommandProcessor(fake).Authenticate(0, make([]byte, 16))
	assert.ErrorIs(t, err, ErrAuthFailed)
}

func TestAuthenticate_OtherFailureIsNotAuthFailed(t *testing.T) {
	fake := newFakeCard(t,
		exchange{capdu: "00A4040C07D2760000850101", rapdu: "9000"},
		exchange{capdu: "9071000002000000", rapdu: "9140"},
	)

	err := NewCommandProcessor(fake).Authenticate(0, make([]byte, 16))
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrAuthFailed)
}

func table19Session(t *testing.T) *session {
	t.Helper()
	return &session{
		encKey: mustHex(t, "1309C877509E5A215007FF0ED19CA564"),
		macKey: mustHex(t, "4C6626F5E72EA694202139295C7A7FC7"),
		ti:     mustHex(t, "9D00C4DF"),
		ctr:    1,
	}
}

func TestSendFull(t *testing.T) {
	fake := newFakeCard(t,
		exchange{capdu: "905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400", rapdu: "57BFF87B1241E93D9100"},
	)

	cp := NewCommandProcessor(fake)
	cp.session = table19Session(t)

	data, err := cp.sendFull(0x5F, []byte{0x02}, mustHex(t, "4000E0C1F121200000430000430000"))
	require.NoError(t, err)
	assert.Empty(t, data)
	assert.Equal(t, uint16(2), cp.session.ctr)
}

func TestSendFull_CorruptedResponseMAC(t *testing.T) {
	fake := newFakeCard(t,
		exchange{capdu: "905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400", rapdu: "57BFF87B1241E93E9100"},
	)

	cp := NewCommandProcessor(fake)
	cp.session = table19Session(t)

	_, err := cp.sendFull(0x5F, []byte{0x02}, mustHex(t, "4000E0C1F121200000430000430000"))
	assert.ErrorIs(t, err, ErrResponseMAC)
}

func TestSendFull_RequiresAuthentication(t *testing.T) {
	cp := NewCommandProcessor(newFakeCard(t))

	_, err := cp.sendFull(0x5F, []byte{0x02}, []byte{0x00})
	assert.ErrorIs(t, err, ErrNotAuthenticated)
}
