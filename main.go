package main

import (
	"fmt"

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
	defer card.Close()

	c := commands.NewCommandProcessor(card)

	check(c.Authenticate(0, make([]byte, 16)))
	check(c.WriteURL("https://www.byjp.me?uid={{uid}}&ctr={{ctr}}&mac={{mac}}", 1))

	msg, err := c.ReadNDEF()
	check(err)

	for _, r := range msg.Records {
		p, err := r.Payload()
		check(err)

		fmt.Println(p.String())
	}
}
