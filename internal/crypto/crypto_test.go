package crypto

import (
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

func TestCMAC_RFC4493(t *testing.T) {
	key := mustHex(t, "2B7E151628AED2A6ABF7158809CF4F3C")

	assert.Equal(t, "070A16B46B4D4144F79BDD9DD04A287C", upperHex(CMAC(key, mustHex(t, "6BC1BEE22E409F96E93D7E117393172A"))))
	assert.Equal(t, "BB1D6929E95937287FA37D129B756746", upperHex(CMAC(key, nil)))
}
