package commands

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/hsanjuan/go-ndef"
	"github.com/jphastings/ntag424/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseURL_PICCAndMAC(t *testing.T) {
	l, err := ParseURL("https://choose.url.com/ntag424?e={{picc}}&c={{mac}}")
	require.NoError(t, err)

	assert.Equal(t, "https://choose.url.com/ntag424?e=00000000000000000000000000000000&c=0000000000000000", l.URL)
	assert.Equal(t, -1, l.UID)
	assert.Equal(t, -1, l.Counter)
	assert.Equal(t, 0x20, l.PICC)
	assert.Equal(t, 0x43, l.MAC)
}

func TestFileSettings_PICCAndMAC(t *testing.T) {
	l, err := ParseURL("https://choose.url.com/ntag424?e={{picc}}&c={{mac}}")
	require.NoError(t, err)

	assert.Equal(t, "40E0EEC1F111200000430000430000", upperHex(fileSettings(l, 1, nil)))
}

func TestParseURL_UIDCounterMAC(t *testing.T) {
	l, err := ParseURL("https://x.example/p?u={{uid}}&c={{ctr}}&m={{mac}}")
	require.NoError(t, err)

	uidStart := strings.Index(l.URL, "u=") + 2
	ctrStart := strings.Index(l.URL, "c=") + 2
	macStart := strings.Index(l.URL, "m=") + 2
	assert.Equal(t, strings.Repeat("0", 14), l.URL[uidStart:uidStart+14])
	assert.Equal(t, strings.Repeat("0", 6), l.URL[ctrStart:ctrStart+6])
	assert.Equal(t, strings.Repeat("0", 16), l.URL[macStart:macStart+16])

	fs := fileSettings(l, 1, nil)
	require.True(t, strings.HasPrefix(upperHex(fs), "40E0EEC1F1E1"))

	offsetBytes := func(off int) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(off))
		return b[:3]
	}
	var expected []byte
	expected = append(expected, 0x40, 0xE0, 0xEE, 0xC1, 0xF1, 0xE1)
	expected = append(expected, offsetBytes(l.UID)...)
	expected = append(expected, offsetBytes(l.Counter)...)
	expected = append(expected, offsetBytes(l.MAC)...)
	expected = append(expected, offsetBytes(l.MAC)...)
	assert.Equal(t, expected, fs)
}

func TestParseURL_Errors(t *testing.T) {
	_, err := ParseURL("https://x.com/{{uid}}{{picc}}")
	assert.ErrorIs(t, err, ErrMirrorConflict)

	_, err = ParseURL("https://x.com/{{uid}}...{{uid}}")
	assert.ErrorIs(t, err, ErrDuplicateMirror)

	_, err = ParseURL("https://x.com/{{nope}}")
	assert.ErrorIs(t, err, ErrUnknownMirror)

	_, err = ParseURL("https://x.com/" + strings.Repeat("a", 300))
	assert.ErrorIs(t, err, ErrNDEFTooLong)
}

func TestParseURL_MACWithoutIdentity(t *testing.T) {
	_, err := ParseURL("https://x.com/?m={{mac}}")
	assert.ErrorIs(t, err, ErrMACWithoutIdentity)

	_, err = ParseURL("https://x.com/?c={{ctr}}&m={{mac}}")
	assert.ErrorIs(t, err, ErrMACWithoutIdentity)

	_, err = ParseURL("https://x.com/?u={{uid}}&m={{mac}}")
	assert.NoError(t, err)

	_, err = ParseURL("https://x.com/?u={{uid}}&c={{ctr}}&m={{mac}}")
	assert.NoError(t, err)

	_, err = ParseURL("https://x.com/?e={{picc}}&m={{mac}}")
	assert.NoError(t, err)
}

func TestParseURL_NoMirrors(t *testing.T) {
	l, err := ParseURL("https://x.com/plain")
	require.NoError(t, err)

	assert.Equal(t, -1, l.UID)
	assert.Equal(t, -1, l.Counter)
	assert.Equal(t, -1, l.PICC)
	assert.Equal(t, -1, l.MAC)
	assert.Equal(t, []byte{0x00, 0xE0, 0xEE}, fileSettings(l, 0, nil))
}

func TestWriteURL_EndToEnd(t *testing.T) {
	url := "https://choose.url.com/ntag424?e={{picc}}&c={{mac}}"

	l, err := ParseURL(url)
	require.NoError(t, err)
	marshalled, err := ndef.NewURIMessage(l.URL).Marshal()
	require.NoError(t, err)

	lenB := make([]byte, 2)
	binary.BigEndian.PutUint16(lenB, uint16(len(marshalled)))

	fake := newFakeCard(t,
		// ChangeFileSettings: fileSettings for this layout differs from the AN12196
		// Table 19 example (F1 11 vs F1 21), but the response MAC only covers
		// SW2/counter/TI, not the command data, so the recorded reply still applies.
		exchange{ins: 0x5F, rapdu: "57BFF87B1241E93D9100"},
		exchange{capdu: "00A4040C07D2760000850101", rapdu: "9000"},
		exchange{capdu: "00A4000C02E104", rapdu: "9000"},
		exchange{capdu: "00D6000002" + upperHex(lenB), rapdu: "9000"},
		exchange{capdu: "00D60002" + upperHex([]byte{byte(len(marshalled))}) + upperHex(marshalled), rapdu: "9000"},
	)

	cp := NewCommandProcessor(fake)
	cp.session = table19Session(t)

	require.NoError(t, cp.WriteURL(url, 1))

	_, err = cp.sendFull(0x5F, []byte{0x02}, nil)
	assert.ErrorIs(t, err, ErrNotAuthenticated, "writing ends the session, so a second secure command must fail cleanly")

	body := marshalled
	piccStart := l.PICC - 2
	assert.Equal(t, "?e=", string(body[piccStart-3:piccStart]))
	assert.Equal(t, strings.Repeat("0", 32), string(body[piccStart:piccStart+32]))

	macStart := l.MAC - 2
	assert.Equal(t, "&c=", string(body[macStart-3:macStart]))
	assert.Equal(t, strings.Repeat("0", 16), string(body[macStart:macStart+16]))
}

func TestFileSettings_ReadLimit(t *testing.T) {
	l, err := ParseURL("https://x.example/p?u={{uid}}&c={{ctr}}&m={{mac}}")
	require.NoError(t, err)

	limit := uint32(0x3E8) // 1000
	withLimit := fileSettings(l, 1, &limit)
	withoutLimit := fileSettings(l, 1, nil)

	offsetBytes := func(off int) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(off))
		return b[:3]
	}
	var expected []byte
	expected = append(expected, 0x40, 0xE0, 0xEE, 0xE1, 0xF1, 0xE1)
	expected = append(expected, offsetBytes(l.UID)...)
	expected = append(expected, offsetBytes(l.Counter)...)
	expected = append(expected, offsetBytes(l.MAC)...)
	expected = append(expected, offsetBytes(l.MAC)...)
	expected = append(expected, 0xE8, 0x03, 0x00)
	assert.Equal(t, expected, withLimit)

	// The two outputs should differ only in the SDMOptions byte and the
	// trailing SDMReadCtrLimit bytes appended for the limited case.
	require.Len(t, withLimit, len(withoutLimit)+3)
	trimmed := append([]byte{}, withLimit[:len(withoutLimit)]...)
	trimmed[3] = withoutLimit[3]
	assert.Equal(t, withoutLimit, trimmed)
	assert.Equal(t, byte(0xC1), withoutLimit[3])
	assert.Equal(t, byte(0xE1), withLimit[3])
}

func TestWriteURL_ReadLimitErrors(t *testing.T) {
	// No exchanges registered: any APDU sent fails the test.
	cp := NewCommandProcessor(newFakeCard(t))

	url := "https://x.example/p?u={{uid}}&c={{ctr}}&m={{mac}}"
	assert.ErrorIs(t, cp.WriteURL(url, 1, WithReadLimit(0x1000000)), ErrReadLimitTooLarge)
	assert.ErrorIs(t, cp.WriteURL(url, 1, WithReadLimit(0)), ErrReadLimitZero)
	assert.ErrorIs(t, cp.WriteURL("https://x.example/plain", 1, WithReadLimit(1000)), ErrReadLimitNeedsMirror)
}

func TestWriteURL_ReadLimit_EndToEnd(t *testing.T) {
	url := "https://x.example/p?u={{uid}}&c={{ctr}}&m={{mac}}"
	limit := uint32(1000)

	l, err := ParseURL(url)
	require.NoError(t, err)
	marshalled, err := ndef.NewURIMessage(l.URL).Marshal()
	require.NoError(t, err)

	lenB := make([]byte, 2)
	binary.BigEndian.PutUint16(lenB, uint16(len(marshalled)))

	fake := newFakeCard(t,
		// As in TestWriteURL_EndToEnd, the response MAC only covers
		// SW2/counter/TI, not the command data, so this recorded reply
		// applies regardless of what ChangeFileSettings data is sent.
		exchange{ins: 0x5F, rapdu: "57BFF87B1241E93D9100"},
		exchange{capdu: "00A4040C07D2760000850101", rapdu: "9000"},
		exchange{capdu: "00A4000C02E104", rapdu: "9000"},
		exchange{capdu: "00D6000002" + upperHex(lenB), rapdu: "9000"},
		exchange{capdu: "00D60002" + upperHex([]byte{byte(len(marshalled))}) + upperHex(marshalled), rapdu: "9000"},
	)

	cp := NewCommandProcessor(fake)
	session := table19Session(t)
	cp.session = session

	require.NoError(t, cp.WriteURL(url, 1, WithReadLimit(limit)))

	sent := fake.sent[0]
	lc := int(sent[4])
	data := sent[5 : 5+lc]
	enc := data[1 : len(data)-8] // strip the file-number header byte and the trailing CMAC

	// session.ctr is 1 at the point sendFull encrypts this command (writing
	// the file clears cp.session afterwards), which is what its IV derives from.
	block, err := aes.NewCipher(session.encKey)
	require.NoError(t, err)
	ivc := make([]byte, aes.BlockSize)
	block.Encrypt(ivc, bytes.Join([][]byte{{0xA5, 0x5A}, session.ti, {1, 0}, make([]byte, 8)}, nil))

	plain := crypto.Unpad(crypto.CBCDecrypt(session.encKey, ivc, enc))

	assert.Equal(t, fileSettings(l, 1, &limit), plain)
	assert.Equal(t, byte(0xE1), plain[3])
	assert.Equal(t, []byte{0xE8, 0x03, 0x00}, plain[len(plain)-3:])
}
