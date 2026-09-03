package validator

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jphastings/ntag424/internal/crypto"
	"github.com/jphastings/ntag424/internal/mirror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var zeroKey = make([]byte, 16)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func upperHex(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

const plainTemplate = "https://www.byjp.me?uid={{uid}}&ctr={{ctr}}&mac={{mac}}"

func TestVerifyURL_PlainMirrors_RealHardware(t *testing.T) {
	cases := []struct {
		uid, ctr, mac string
		counter       uint32
	}{
		{"043C30FA2D6B80", "000006", "C5A5980927E41003", 6},
		{"043C30FA2D6B80", "00000A", "3894FCE7C78C44F2", 10},
		{"043C30FA2D6B80", "00000B", "BD656E26ECF0E5A5", 11},
	}

	for _, c := range cases {
		url := "https://www.byjp.me?uid=" + c.uid + "&ctr=" + c.ctr + "&mac=" + c.mac
		tap, err := VerifyURL(url, plainTemplate, zeroKey)
		require.NoError(t, err)
		require.NotNil(t, tap)
		assert.Equal(t, mustHex(t, c.uid), tap.UID)
		assert.Equal(t, c.counter, tap.Counter)
	}
}

const encryptedTemplate = "https://www.byjp.me?e={{picc}}&c={{mac}}"

func TestVerifyURL_EncryptedMirror_RealHardware(t *testing.T) {
	url := "https://www.byjp.me?e=C25BF4B2C76F3EDD0127340C4D415F36&c=74FD7AC8478BD0B3"

	tap, err := VerifyURL(url, encryptedTemplate, zeroKey)
	require.NoError(t, err)
	require.NotNil(t, tap)
	assert.Equal(t, mustHex(t, "043C30FA2D6B80"), tap.UID)
	assert.Equal(t, uint32(8), tap.Counter)
}

func TestVerify_EncryptedMirror_AN12196Table3(t *testing.T) {
	v := Values{
		PICC: "EF963FF7828658A599F3041510671E88",
		MAC:  "94EED9EE65337086",
	}

	tap, err := Verify(v, zeroKey)
	require.NoError(t, err)
	require.NotNil(t, tap)
	assert.Equal(t, mustHex(t, "04DE5F1EACC040"), tap.UID)
	assert.Equal(t, uint32(61), tap.Counter)
}

// AN12196 Table 2: the session MAC key derived from SV2 = 3CC3000100 80 || UID || counter (LSB-first).
func TestSessionMACKeyDerivation_AN12196Table2(t *testing.T) {
	key := mustHex(t, "5ACE7E50AB65D5D51FD5BF5A16B8205B")
	uid := mustHex(t, "04C767F2066180")
	counterLSBFirst := mustHex(t, "010000")

	sv2 := append([]byte{0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80}, uid...)
	sv2 = append(sv2, counterLSBFirst...)

	sessionMAC := crypto.CMAC(key, sv2)
	assert.Equal(t, "3A3E8110E05311F7A3FCF0D969BF2B48", upperHex(sessionMAC))
}

func TestVerifyURL_Success(t *testing.T) {
	url := "https://www.byjp.me?uid=043C30FA2D6B80&ctr=00000B&mac=BD656E26ECF0E5A5"

	tap, err := VerifyURL(url, plainTemplate, zeroKey)
	require.NoError(t, err)
	require.NotNil(t, tap)
	assert.Equal(t, mustHex(t, "043C30FA2D6B80"), tap.UID)
	assert.Equal(t, uint32(11), tap.Counter)
}

func TestVerifyURL_FlippedMACCharacter(t *testing.T) {
	url := "https://www.byjp.me?uid=043C30FA2D6B80&ctr=00000B&mac=BD656E26ECF0E5A4"

	tap, err := VerifyURL(url, plainTemplate, zeroKey)
	assert.ErrorIs(t, err, ErrMACMismatch)
	assert.Nil(t, tap)
}

func TestVerifyURL_DifferentHost(t *testing.T) {
	url := "https://evil.example?uid=043C30FA2D6B80&ctr=00000B&mac=BD656E26ECF0E5A5"

	tap, err := VerifyURL(url, plainTemplate, zeroKey)
	assert.ErrorIs(t, err, ErrTemplateMismatch)
	assert.Nil(t, tap)
}

func TestVerifyURL_WrongLength(t *testing.T) {
	url := "https://www.byjp.me?uid=043C30FA2D6B80&ctr=00000B&mac=BD656E26ECF0E5A5extra"

	tap, err := VerifyURL(url, plainTemplate, zeroKey)
	assert.ErrorIs(t, err, ErrTemplateMismatch)
	assert.Nil(t, tap)
}

func TestVerifyURL_MACWithoutIdentity(t *testing.T) {
	tap, err := VerifyURL("https://x.com/?m=0000000000000000", "https://x.com/?m={{mac}}", zeroKey)
	assert.ErrorIs(t, err, mirror.ErrMACWithoutIdentity)
	assert.Nil(t, tap)
}

func TestVerifyURL_WrongKey(t *testing.T) {
	url := "https://www.byjp.me?uid=043C30FA2D6B80&ctr=00000B&mac=BD656E26ECF0E5A5"
	wrongKey := make([]byte, 16)
	wrongKey[0] = 0x01

	tap, err := VerifyURL(url, plainTemplate, wrongKey)
	assert.ErrorIs(t, err, ErrMACMismatch)
	assert.Nil(t, tap)
}

func TestVerify_KeyLength(t *testing.T) {
	_, err := Verify(Values{UID: "043C30FA2D6B80", MAC: "BD656E26ECF0E5A5"}, make([]byte, 10))
	assert.Error(t, err)
}

func TestVerify_MissingMAC(t *testing.T) {
	tap, err := Verify(Values{UID: "043C30FA2D6B80"}, zeroKey)
	assert.ErrorIs(t, err, ErrMissingMAC)
	assert.Nil(t, tap)
}

func TestVerify_MissingIdentity(t *testing.T) {
	tap, err := Verify(Values{MAC: "BD656E26ECF0E5A5"}, zeroKey)
	assert.ErrorIs(t, err, ErrMissingIdentity)
	assert.Nil(t, tap)
}

func TestVerify_Malformed(t *testing.T) {
	tap, err := Verify(Values{UID: "notHex", MAC: "BD656E26ECF0E5A5"}, zeroKey)
	assert.ErrorIs(t, err, ErrMalformed)
	assert.Nil(t, tap)

	tap, err = Verify(Values{UID: "043C30FA2D6B80", MAC: "notHex"}, zeroKey)
	assert.ErrorIs(t, err, ErrMalformed)
	assert.Nil(t, tap)
}
