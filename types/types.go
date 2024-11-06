package types

import "github.com/skythen/apdu"

type Card interface {
	SendCommand(*apdu.Capdu) (*apdu.Rapdu, error)
}
