package types

import "github.com/skythen/apdu"

type Card interface {
	SendCommandAPDU(*apdu.Capdu) (*apdu.Rapdu, error)
}
