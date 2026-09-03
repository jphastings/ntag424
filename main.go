package main

import (
	"fmt"

	"github.com/hsanjuan/go-ndef"
	"github.com/jphastings/ntag424/cards"
	"github.com/jphastings/ntag424/commands"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	card, err := cards.NewScard()
	check(err)

	c := commands.NewCommandProcessor(card)

	check(c.WriteNDEF(ndef.NewURIMessage("https://www.byjp.me?uid={{uid}}")))

	msg, err := c.ReadNDEF()
	check(err)

	for _, r := range msg.Records {
		p, err := r.Payload()
		check(err)

		fmt.Println(p.String())
	}

}
