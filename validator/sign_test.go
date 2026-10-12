package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSign_VerifiesAsTheSameTap(t *testing.T) {
	key := mustHex(t, "5ACE7E50AB65D5D51FD5BF5A16B8205B")
	uid := mustHex(t, "04C767F2066180")

	for name, values := range map[string]Values{
		"plain":     Sign(uid, 42, key),
		"encrypted": SignEncrypted(uid, 42, key),
	} {
		t.Run(name, func(t *testing.T) {
			tap, err := Verify(values, key)
			require.NoError(t, err)
			assert.Equal(t, uid, tap.UID)
			assert.Equal(t, uint32(42), tap.Counter)
		})
	}
}

// AN12196 §3.4.4.2.1: the MAC a tag with a zero key writes for UID
// 04DE5F1EACC040 on its 61st read.
func TestSign_MatchesAN12196(t *testing.T) {
	values := Sign(mustHex(t, "04DE5F1EACC040"), 61, zeroKey)
	assert.Equal(t, "04DE5F1EACC040", values.UID)
	assert.Equal(t, "00003D", values.Counter)
	assert.Equal(t, "94EED9EE65337086", values.MAC)
}

func TestSign_OtherKeyFails(t *testing.T) {
	values := Sign(mustHex(t, "04C767F2066180"), 1, zeroKey)
	_, err := Verify(values, mustHex(t, "5ACE7E50AB65D5D51FD5BF5A16B8205B"))
	assert.ErrorIs(t, err, ErrMACMismatch)
}
