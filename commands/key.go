package commands

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// changeKeyCRC computes the CRC32 that ChangeKey appends to KeyData when
// changing a key other than the one authenticated with. NXP specifies the
// IEEE 802.3 FCS value, which is the bitwise NOT of Go's ChecksumIEEE, and it
// goes on the wire least significant byte first.
func changeKeyCRC(newKey []byte) []byte {
	crc := ^crc32.ChecksumIEEE(newKey)
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, crc)
	return out
}

// ChangeKey replaces key keyNo's value on the tag with newKey, tagged with
// version. The tag requires you to authenticate with key 0 before changing
// any key. version is stored alongside the key and is yours to choose, to
// track which value is currently on the tag.
//
// Changing a key is irreversible without the new value: lose newKey and the
// tag can never be reconfigured again. oldKey must be keyNo's current
// 16-byte AES-128 key, unless keyNo is the key Authenticate used, in which
// case oldKey is unused and may be nil.
//
// Changing the key just authenticated with ends the session: the tag can no
// longer MAC a reply with keys that have just been replaced, so ChangeKey
// clears cp's session and callers must Authenticate again, with newKey,
// before issuing further commands.
func (cp *CommandProcessor) ChangeKey(keyNo byte, oldKey, newKey []byte, version byte) error {
	if keyNo > 4 {
		return ErrInvalidKeyNo
	}
	if cp.session == nil {
		return ErrNotAuthenticated
	}
	if len(newKey) != 16 {
		return fmt.Errorf("newKey must be 16 bytes, got %d", len(newKey))
	}

	changingOwnKey := keyNo == cp.session.keyNo

	var keyData []byte
	if changingOwnKey {
		keyData = append(append([]byte{}, newKey...), version)
	} else {
		if len(oldKey) != 16 {
			return ErrOldKeyRequired
		}
		keyData = append(xorBytes(newKey, oldKey), version)
		keyData = append(keyData, changeKeyCRC(newKey)...)
	}

	if _, err := cp.sendFullOpt(0xC4, []byte{keyNo}, keyData, !changingOwnKey); err != nil {
		return err
	}

	if changingOwnKey {
		cp.session = nil
	}

	return nil
}
