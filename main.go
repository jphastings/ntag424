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

	check(c.WriteNDEF(ndef.NewURIMessage("https://www.byjp.me")))

	msg, err := c.ReadNDEF()
	check(err)

	for _, r := range msg.Records {
		p, err := r.Payload()
		check(err)

		fmt.Println(p.String())
	}

	// c, err := ConnectToCard()
	// check(err)

	// // Write
	// if false { // Page 65
	// 	// The NDEF file
	// 	fileNumber := 2
	// 	// Enable Secure Dynamic Messaging
	// 	fileOption := 1 << 6
	// 	// Permissions: free access to read, write, readwrite but not change (default) — Page 11
	// 	access := []byte{0xEE, 0xE0}

	// 	sdmOpts := 1<<7 + // Mirror UID
	// 		1<<6 + // Mirror Counter
	// 		1 // ASCII encoding

	// 	sdmAccessRights := []byte{
	// 		// Plain PICC mirroring; no SDM for reading
	// 		0xEF,
	// 		// Free reading of counter
	// 		0x0E,
	// 	}

	// 	uidOffset := 44
	// 	counterOffset := 58

	// 	// TODO: Do this as 32 bit numbers and clip the top byte
	// 	var buf bytes.Buffer
	// 	buf.Write([]byte{0x00})
	// 	binary.Write(&buf, binary.BigEndian, uidOffset)

	// 	buf.Write([]byte{0x00})
	// 	binary.Write(&buf, binary.BigEndian, counterOffset)

	// 	_, err = c.SendCommand(&apdu.Capdu{
	// 		Cla: 0x90, Ins: 0x5F, P1: 0x00, P2: 0x00,
	// 		Data: append(
	// 			[]byte{
	// 				byte(fileNumber), byte(fileOption),
	// 				access[0], access[1],
	// 				byte(sdmOpts), sdmAccessRights[0], sdmAccessRights[1],
	// 			},
	// 			buf.Bytes()...,
	// 		),
	// 	})
	// 	check(err)

	// } else {

	// 	_, err = c.SendCommand(SelectApplication(ndefID))
	// 	check(err)

	// 	_, err = c.SendCommand(SelectFile(ntag424NDEFFileID))
	// 	check(err)

	// 	msg, err := c.ReadNDEFs()
	// 	check(err)

	// 	for _, r := range msg.Records {
	// 		p, err := r.Payload()
	// 		check(err)

	// 		fmt.Println(p.String())
	// 	}
	// }

}
