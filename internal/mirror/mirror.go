// Package mirror holds the single source of truth for NTAG 424 DNA Secure
// Dynamic Messaging placeholders: their text form, the length each expands
// to, and the rules governing which combinations a tag accepts.
package mirror

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Placeholders the tag replaces at read time. Each expands to the ASCII-hex length the tag writes.
const (
	UID     = "{{uid}}"  // 14 hex chars: the 7-byte UID
	Counter = "{{ctr}}"  // 6 hex chars: the 3-byte read counter (LSB first)
	PICC    = "{{picc}}" // 32 hex chars: AES-encrypted UID + counter; cannot be combined with {{uid}} or {{ctr}}
	MAC     = "{{mac}}"  // 16 hex chars: truncated AES-CMAC
)

var lengths = map[string]int{
	UID:     14,
	Counter: 6,
	PICC:    32,
	MAC:     16,
}

// Errors returned by Expand.
var (
	ErrUnknown            = errors.New("unknown mirror placeholder")
	ErrDuplicate          = errors.New("mirror placeholder used more than once")
	ErrConflict           = errors.New("{{picc}} cannot be combined with {{uid}} or {{ctr}}")
	ErrMACWithoutIdentity = errors.New("{{mac}} needs {{uid}} and {{ctr}}, or {{picc}}, to sign")
)

var placeholderRe = regexp.MustCompile(`\{\{[^}]*\}\}`)

// Positions holds the index of each placeholder within the expanded string. -1 means absent.
type Positions struct {
	UID, Counter, PICC, MAC int
}

// Expand replaces each placeholder with a run of '0' of the length the tag writes,
// and reports where each one starts in the expanded string.
func Expand(template string) (string, Positions, error) {
	positions := map[string]int{}
	seen := map[string]bool{}

	var b strings.Builder
	prev := 0
	for _, m := range placeholderRe.FindAllStringIndex(template, -1) {
		start, end := m[0], m[1]
		token := template[start:end]

		n, ok := lengths[token]
		if !ok {
			return "", Positions{}, fmt.Errorf("%w: %s", ErrUnknown, token)
		}
		if seen[token] {
			return "", Positions{}, fmt.Errorf("%w: %s", ErrDuplicate, token)
		}
		seen[token] = true

		b.WriteString(template[prev:start])
		positions[token] = b.Len()
		b.WriteString(strings.Repeat("0", n))
		prev = end
	}
	b.WriteString(template[prev:])
	expanded := b.String()

	if seen[PICC] && (seen[UID] || seen[Counter]) {
		return "", Positions{}, ErrConflict
	}
	// The tag derives the signing key from the UID and counter, so with
	// neither mirrored the signature would be the same on every read; a
	// real tag rejects this configuration with status 0x919E.
	if seen[MAC] && !seen[UID] && !seen[Counter] && !seen[PICC] {
		return "", Positions{}, ErrMACWithoutIdentity
	}

	p := Positions{UID: -1, Counter: -1, PICC: -1, MAC: -1}
	if pos, ok := positions[UID]; ok {
		p.UID = pos
	}
	if pos, ok := positions[Counter]; ok {
		p.Counter = pos
	}
	if pos, ok := positions[PICC]; ok {
		p.PICC = pos
	}
	if pos, ok := positions[MAC]; ok {
		p.MAC = pos
	}

	return expanded, p, nil
}
