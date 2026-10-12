# ntag424

A Go package that writes dynamic, verifiable URLs to NXP NTAG 424 DNA tags.

## The advantage over ordinary NFC tags

An ordinary NFC tag holds a fixed URL. Two things follow from this.

Anyone who taps the tag can then share that link, which works the same way for everyone, wherever they got it from. There is no proof the visitor had the card.

Anyone can also copy the URL onto a blank tag. The copy and the first tag give
the same answer, so your server cannot tell them apart.

## What the DNA tags add

An NTAG 424 DNA tag holds a secret AES key. The key cannot leave the chip.
The tag rewrites part of its URL on each tap. Three pieces of data go into the
URL:

1. The serial number of the tag.
2. A counter, which increases on each read.
3. A signature that covers the serial number and the counter.

The tag does this work by itself, in the moment a phone reads it. No app and no
network connection are necessary.

Your server checks the signature with its copy of the key. This gives you four
useful guarantees:

- **Proof of touch.** Only a person who holds the real tag can produce a new
  and correct URL.
- **Copy protection.** A cloned tag has no key, so it cannot sign the data. The
  signature check then fails.
- **Replay detection.** The counter increases on each read. An old link carries
  a low counter, and your server can refuse it.
- **Optional privacy.** The tag can encrypt the serial number and the counter.
  Only your server then knows which tag a person tapped.

NXP calls this feature Secure Dynamic Messaging, or SDM. A URL made this way is
a Secure Unique NFC message, or SUN.

## How this package works

You write a URL that contains placeholders. Each placeholder marks the place
where the tag writes a value.

| Placeholder | The tag writes                                  | Length | Needs a key |
| ----------- | ----------------------------------------------- | ------ | ----------- |
| `{{uid}}`   | The serial number of the tag.                   | 14     | No          |
| `{{ctr}}`   | The read counter.                               | 6      | No          |
| `{{picc}}`  | The serial number and counter, encrypted.       | 32     | Yes         |
| `{{mac}}`   | A signature over the serial number and counter. | 16     | Yes         |

The tag writes hexadecimal text. Each value is therefore two characters per
byte. A serial number of seven bytes becomes fourteen characters.

The package expands each placeholder to its full length before the write. The
stored URL therefore holds a run of zeros at each placeholder. The tag writes
over those zeros when a phone reads the tag.

Use `{{picc}}`, or use `{{uid}}` and `{{ctr}}`. You cannot combine the two styles.
There is no value in a tag holding both the encrypted values (`{{picc}}`) and the plain text equivalents (`{{uid}}`, `{{ctr}}`).

`{{mac}}` also needs the serial number beside it, as `{{uid}}` or inside
`{{picc}}`. The tag only signs the serial number when the URL carries it, and
your server needs it to check the signature. A template with a signature but no
`{{uid}}` or `{{picc}}` is therefore rejected, even if it has `{{ctr}}`.

## Example

```go
package main

import (
	"fmt"
	"log"

	"github.com/jphastings/ntag424/cards"
	"github.com/jphastings/ntag424/commands"
)

func main() {
	card, err := cards.NewScard()
	if err != nil {
		log.Fatal(err)
	}
	defer card.Close()

	tag := commands.NewCommandProcessor(card)

	// A new tag has sixteen zero bytes as its key.
	if err := tag.Authenticate(0, make([]byte, 16)); err != nil {
		log.Fatal(err)
	}

	url := "https://example.com/tap?uid={{uid}}&ctr={{ctr}}&mac={{mac}}"

	// The second argument selects the key that signs each tap.
	if err := tag.WriteURL(url, 1); err != nil {
		log.Fatal(err)
	}

	fmt.Println("The tag is ready. Tap it with a phone.")
}
```

A phone that reads that tag opens a URL of this shape:

```
https://example.com/tap?uid=043C30FA2D6B80&ctr=00000B&mac=BD656E26ECF0E5A5
```

Each tap produces a different counter and a different signature.

## How your server checks a tap

The `validator` package does this work. Give it the URL from the tap, the
template you wrote to the tag, and your key.

```go
package main

import (
	"fmt"
	"log"

	"github.com/jphastings/ntag424/validator"
)

const template = "https://example.com/tap?uid={{uid}}&ctr={{ctr}}&mac={{mac}}"

func main() {
	tapped := "https://example.com/tap?uid=043C30FA2D6B80&ctr=00000B&mac=BD656E26ECF0E5A5"

	tap, err := validator.VerifyURL(tapped, template, make([]byte, 16))
	if err != nil {
		log.Fatal("this tap is not genuine: ", err)
	}

	fmt.Printf("tag %X, read number %d\n", tap.UID, tap.Counter)
}
```

That program prints:

```
tag 043C30FA2D6B80, read number 11
```

The validator compares the fixed parts of the URL against the template, as well
as the signature. A link from another host therefore fails, even when the
signature itself is correct.

Your handler may already hold the values as separate query parameters. Pass
them to `validator.Verify` instead:

```go
tap, err := validator.Verify(validator.Values{
	UID:     query.Get("uid"),
	Counter: query.Get("ctr"),
	MAC:     query.Get("mac"),
}, key)
```

For an encrypted tag, set the `PICC` field instead of `UID` and `Counter`. Both
functions return an error and no tag data when the signature fails, so a caller
cannot read a serial number that nothing vouched for.

The `validator` package needs only the standard library. A server that checks
taps therefore does not pull in the card reader code.

The NXP application note AN12196 describes the calculation in full. Some open
source verifiers already do this work, for example
[sdm-backend](https://github.com/icedevml/sdm-backend).

## Keys

The tag stores five AES-128 keys in slots numbered zero to four. Every slot
holds sixteen zero bytes when the tag leaves the factory. Slot zero is the
administrator key, and the tag asks for it before it changes any setting or any
key. Slots one to four are yours to use for signing.

Two different things travel under the name "key", and the difference matters. A
key *number* says which slot to use. A key *value* is the sixteen secret bytes
in that slot. `WriteURL` takes a number, while `Authenticate` and the validator
take a value.

A normal session proves the value of slot zero, then asks the tag to sign with
slot one:

```go
tag.Authenticate(0, adminKey) // the value held in slot 0
tag.WriteURL(url, 1)          // slot 1 signs each tap
```

Your server then verifies each tap with the value held in slot one.

## Changing a key

`ChangeKey` replaces the value in a slot. Authenticate with slot zero first,
whichever slot you go on to change:

```go
tag.Authenticate(0, adminKey)

// The tag needs the old value as well as the new one.
err := tag.ChangeKey(1, oldSigningKey, newSigningKey, 1)
```

The last argument is a version number of your choosing. The tag stores it next
to the key, so you can tell which value a tag currently holds.

Change slot zero last, and pass nil in place of the old value:

```go
err := tag.ChangeKey(0, nil, newAdminKey, 1)
```

That call ends the session, because the tag can no longer answer using keys it
has just replaced. Authenticate again with the new value before you continue.

Record the new values before you send them. Lose the administrator key and you
lose the tag. You cannot change its settings, you cannot change its keys back,
and you cannot lift a read limit. Nothing recovers it.

## Limiting the number of taps

A tag can refuse to work after a set number of reads. Pass `WithReadLimit` when
you write the URL:

```go
err := tag.WriteURL(url, 1, commands.WithReadLimit(500))
```

Treat this feature with care. Once the counter reaches the limit, the tag
refuses every read from a normal reader. It returns a "security status not
satisfied" error rather than the URL, so the visitor sees nothing at all.
Anyone who holds the tag can reach that limit on purpose, so NXP describes the
feature as a denial-of-service risk.

A locked tag is not a lost tag. Writing settings never reads them, so you can
always recover one. Authenticate, then write the URL again without the option:

```go
err := tag.WriteURL(url, 1)
```

The package rejects a limit of zero, because such a tag would refuse its very
first read.

## Resetting the count

The counter only counts up, and no command sets it to a value you choose.
Writing a new URL to a tag that already uses Secure Dynamic Messaging leaves the
count alone.

The tag does clear the counter when the feature turns on. Use that to start
again from zero. First write a URL with no placeholders, which turns the feature
off. Then write your real URL, which turns it back on:

```go
// Each write needs its own Authenticate. See Limitations.
tag.Authenticate(0, key)
tag.WriteURL("https://example.com/", 1) // no placeholders, so the feature turns off

tag.Authenticate(0, key)
tag.WriteURL(url, 1) // the feature turns on, and the count starts at zero
```

## Requirements

The package talks to a PC/SC card reader through
[ebfe/scard](https://github.com/ebfe/scard). macOS includes PC/SC. Linux needs
the `pcscd` daemon.

`NewScard` connects to a tag already on the first reader. `WaitForCard`
instead waits for a tag to arrive, on a reader named by `Readers`, until its
context ends. Both claim the reader for your program alone. Call `Close` to
hand it back, as the example does. Until you do, nothing else can reach the
reader, not even another connection in the same program.

`UID` asks the reader for the serial number of the tag. It needs no key.

## Limitations

Call `Authenticate` before each call to `WriteURL`. The tag ends the
authenticated session when the package selects a file.

The package leaves the access rights of the tag at their factory values, so
read and write access stay open to everyone. Anyone can therefore rewrite the
URL on a tag they hold. Use `ChangeKey` to move a tag off its factory keys, or
anyone can forge a signature as well.

The NDEF file of the tag holds 256 bytes. A longer URL returns
`ErrNDEFTooLong`.

This package does not include the LRP cipher mode or the encrypted file data
mirror.
