# Dual Secure Elements

## Background

The **COLDCARD<sup>&reg;</sup>** Mk4 and Q have two secure elements:  

- SE1 (Secure Element 1): Microchip ATECC608
- SE2 (Secure Element 2): Maxim DS28C36B

Because different vendors make them, they do not share bugs and weaknesses.

Although Mk3 uses the SE1 chip, Mk4 uses it a little differently.
SE2 is an entirely new chip, never previously deployed in a COLDCARD.
Both chips use secp256r1 for Elliptic-curve Cryptography (ECC) and
HMAC-SHA256.

## Design Goals

### The Assumption

Assume attackers have physical access to a COLDCARD, have opened
the case, and can probe the bus connections between the MCU and SE1
or SE2. They may even de-solder SE1 and SE2 from the board, and put
active circuits between them and the MCU &mdash; an active MiTM attack.


### The Solutions

Three parties hold secrets in the COLDCARD: the main MCU (microcontroller)
and the two secure elements. Our goal is that **all three** must
be fully compromised to access the seed words. Thus, if one part
has a vulnerability, the COLDCARD as a whole is still secure.
Additionally, knowledge of the correct PIN code is required, even
if all three devices are cracked wide open. (This is a last line
of defence, a brute-force attack on all PIN combinations will breach
it.)

COLDCARD also supports new Trick PIN codes with side effects such
as wiping or bricking the COLDCARD, or providing access to a decoy
or duress wallet. Ideally, attackers will not detect using a false
PIN, even while probing the signals on the board.


## MCU vs. SE1 and SE2

As in Mk1 through Mk3 of the COLDCARD, the MCU has a Pairing Secret.
The MCU uses the Pairing Secret to authenticate itself to SE1 and
vice versa. Flash memory holds the 32-byte Pairing Secret in a
protected area. Only the boot loader code can access this memory,
and the MicroPython code cannot read this area of the chip. Using
an internal firewall feature and PCROP (proprietary code readout
protection) achieves this result.

COLDCARD also shares a secret between SE2 and the MCU. Just like SE1,
this authenticates SE2 to the MCU and encrypts their mutual
communications. The Pairing Secret for SE2 is not stored in SE1 and
is unique from the other Pairing Secret used for SE1.

These Pairing Secrets secure the electrical connections between
SE1, SE2, and the MCU probing attempts. In practice, this means
most commands and responses are XOR'ed with an HMAC-SHA256 value
where the HMAC key is the Pairing Secret and the message is a hash
of the command arguments.

There are also cases where an ECC signature and ECDH establish a
shared secret between devices.


## Seed Decryption

SE1 still holds the seed words, but they are AES-encrypted, and SE1
does not contain a key to decrypt it. The MCU and SE2 store the
seed word decryption key. To access the AES key held in SE2, SE1
has to perform a public key signature and ECDH setup, which requires
the main PIN code. The MCU will only provide its key if both SE1
and SE2 are satisfied.

Earlier COLDCARD versions XOR-ed the stored value with a secret in
the MCU (one-time pad), but this new approach is more powerful
because it mixes in values from the SE2 and MCU using AES; this
increases flexibility and resistance to known plain text attacks.


## All the Keys

| Symbol                | Chip's Name         | Type         | Holder   | Purpose
|-----------------------|---------------------|--------------|----------|----------
| `SE1 pairing`         | slot 1              | HMAC         | SE1, MCU | Protects communications between SE1 and MCU
| `SE2 pairing`         | secret A            | HMAC         | SE2, MCU | Pairing for SE2
| `SE2 comms`           | keypair A           | ECC          | SE2      | MCU captures pubkey half, used in ECDH comms
| `SE joiner`           | slot 7, pubkey C    | ECC          | SE1/SE2  | SE2 knows only public part, SE1 has privkey
| `pin stretch`         | slot 2              | HMAC         | SE1      | Key stretching for PIN entry and anti-phish words
| `firmware`            | slot 14             | SHA256d      | SE1      | Firmware checksum, controls green/red LEDs
| `nonce/chksum`        | slot 10             | data         | SE1      | AES nonce and GMAC tag, protected by PIN
| `SE2 easy key`        | page 15             | AES via HMAC | SE2      | Another SE2 part of AES seed key
| `SE2 hard key`        | page 14             | AES via ECC  | SE2      | SE2's part of AES seed key; ECC used to unlock
| `tpin key`            | `tpin_key`          | HMAC(key)    | MCU      | Key for HMAC used to encrypt trick PINs
| `trick PIN slots`     | pages 0-12          | HMAC         | SE2      | Protect duress wallet seeds and pins (6 spots)
| `SE2 trash`           | secret B            | HMAC         | SE2      | Used to destroy values (only SE2 knows the value)
| `hash cache secret`   | `hash_cache_secret` | XOR/AES      | MCU      | In-memory encryption of actual PIN when unlocked
| `mcu hmac key`        | `mcu_hmac_key`      | HMAC         | MCU      | Used as HMAC key to compress other keys
| `replaceable mcu key` | `MCU_KEYS`          | AES          | MCU      | Replaceable MCU key (up to 256 times)

All keys listed are 32 bytes long and picked randomly using the hardware RNG.

An entered PIN code goes through the same hashing process as with
previous COLDCARD versions. This involved process uses a value in
SE1 for key stretching purposes. Before the final hashed PIN value
unlocks a few slots in SE1, `MCU pin check` HMACs the hashed PIN
value and uses the result to check for Trick PINs in SE2. If no
Trick PINs decode in SE2's memory, the PIN is tested against SE1.

If the PIN is correct:

- The the PIN-attempt counter resets to 13 attempts remaining.
- The `SE joiner` slot on SE1 establishes ECDH communication between the MCU and SE1.
- `SE joiner` authorizes the page on SE2 holding `SE2 seed key`.

The `SE2 seed key` value and the `MCU seed key` are now available
to decrypt the seed words unlocked by the PIN.

These sources combine to create the final seed decryption key:

k = HMAC-SHA256 (key = (`mcu hmac key`), msg = (`SE2 easy key` + `SE2 hard key` + current `replaceable mcu key`))

### AES Details

COLDCARD uses AES-256 in
[CTR mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)).
Message authentication involves adding 32 bytes of zeros to the
end of the message and checking they decode correctly.

A new keyslot, 10, stores the MAC data (encrypted zeros).

The starting nonce for CTR mode is fixed random value composed of
the first 15 bytes of the `mcu hmac key`, followed by a zero (this
increments if more than 16 bytes are encrypted or decrypted).


### MCU Keys

There are two keys in the MCU that affect the seed, the `mcu hmac
key`, and the `replaceable mcu key`.

The `mcu hmac key` is fixed at factory setup time. It acts as the key for
an HMAC operation that compresses the seed key.

The `replaceable mcu keys` are picked at runtime and saved to flash.
There is only one key active at a time, but there are a few slots
in flash for new ones.  When the COLDCARD performs a wipe, it clears
the current `mcu replaceable key`. That process is very fast and
does not have any external signals to betray it's occurring. There
is no need to clear the keys in SE2 or SE1 since without the `mcu
replaceable key`, the actual AES key is still unknown.

New COLDCARDs will ship from the factory with no key picked yet.
Once the main PIN is set and a wallet imported or created, the
first `mcu replaceable key` is picked.

Each wipe operation consumes a replaceable key, and there are a limited
number of them (256) available during the life of the COLDCARD.


### Captured values

The MCU captures public and semi-public values and prohibits them
from changing. These include:

- SE1 and SE2 chip serial numbers (used in most HMAC responses, fully public)
- The public key for `SE joiner` and `SE2 comms` key pairs

Logically, these values are potentially readable at runtime. Since
they are not expected to change, storing them assures they will not
change when under attack (perhaps by substituting a different part).

Blocking the values from read-back out of the secure element is
done where possible.


## Trick PINs

Supporting certain COLDCARD features requires several distinct PIN
codes with various side effects, such as:

- Unlocking a duress wallet
- Triggering a long login delay
- Bricking the COLDCARD
- Blanking the COLDCARD

SE2's even-numbered pages store these PINs with the adjacent odd
slot holding the corresponding secret. The MCU tries each PIN a
user enters against all the slots and works silently to support the
Trick features.

The type of support depends on the type of Trick. Duress wallets
require storing 32 or 64 bytes of seed words (generated from the true
seed via BIP-85). Other cases dictate encoding a short numeric code
provided to higher layers for implementation. For example, a flag
in that code can trigger the boot ROM to wipe the `mcu seed key`.
External actors cannot interrupt or monitor this change because it
is internal to the MCU. The `mcu seed key` is as critical as the
other parts of the AES key to access the seed words. The `mcu seed
key` being zero makes the seed permanently inaccessible.

The MCU code may continue speaking to SE1 to complete the fraud,
but in general, SE1 will no longer store the duress wallet or Brick
Me PINs as in previous generations (Mk1-3). Mk4 and Q implement
those feature in SE2.


### Trick PIN Operation

When a PIN is entered, it is hashed through a series of operations
that take a round trip to SE1. This is the same as the Mk3 using
its secure element for key stretching. A 32-byte deterministic hash,
dependent on secrets from the main MCU and SE1 and unique to each
COLDCARD, is returned. The hash is compared against all 14 of the
slots in SE2.

A few least significant bits (LSB) are masked out of the hash. If
the PIN entered matches one of the slots, the masked-out bits are
checked. Based on the check, two values are taken: `tc_arg` and
`tc_flags`. These two values implement flags and arguments
required to implement the Trick PIN features.


### Trick PIN slot data

The flags are checked along with their corresponding arguments if
a match is found while iterating through all the slots. Some flags
are implemented directly in the boot loader before anything is sent
to Micropython. Other flags are passed to Micropython for implementation
or are implemented in both the boot ROM and Micropython.

**Example 1** A flag is set for Fast Wipe and an attacker has control
of the I2C-bus going to SE2 and the one-wire bus going to SE1. They
can attempt to block the wipe in hopes of trying different PINs
without damaging anything, but they will fail. If `tc_flags`, which
is a bitmask, indicates a Fast Wipe, the seed wiping happens inside
the main MCU. It clears data inside the main MCU extremely quickly
and with no external signals &mdash; either before or after &mdash;
to indicate it happened. This prevents blocking Fast Wipe.

**Example 2** The login countdown feature allows specifying a Trick
PIN. When the Trick PIN is entered, the COLDCARD will show a countdown
timer and the time that must elapse before logging in is allowed.
`tc_arg` encodes the number of minutes on the delay.

**Example 3** Although SE2 holds the Trick PINs, it does not know
the True PIN and Delta Mode will not reveal the full True PIN. The
"Delta Mode" Trick PIN has its unique hash result, and an entry from SE1 is used
to calculate the True PIN. This is accomplished by masking out the
last four digits of the hash and substituting four digits from
`tc_arg`. Limiting it to four digits enables a difference between
the Delta PIN and the True PIN.

This makes the True PIN unknowable without knowing the Delta Mode
Trick PIN; SE2 cannot be searched for the True PIN and generating
the PIN hashes for SE2 would only be possible after cracking SE1
and the main MCU.


## Spare Slots

Moving the duress wallet and Brick Me PINs to SE2 left free storage
inside SE1. This storage is called Spare Secrets. Spare Secrets has
3 &times; 72 bytes of space, protected by the same measures as the
seed words.

Mk4/Q still supports the Long Secret (416 bytes), but its API is
changed. The slow speed of fetching the Long Secret in 32-byte
blocks due to the reconstructing the primary AES Seed Key for each
call necessitated the change.


## Observations

It's essential that SE2 cannot validate a PIN code. Brute-forcing
SE2 would be easy because it lacks SE1's rate limiting (or usage
counter), so SE2 only stores Trick PINs. Testing against the Trick
PINs would require compromising the MCU. Due to SE2's performance,
the maximum attempt rate would be 6 ms. However, controlling the
MCU makes that testing pointless to such an attacker; they could
just NOP-out the Trick PIN checking.

A user expecting attackers smart enough to crack open the case and
monitor the buses should provide a Trick PIN that wipes the COLDCARD's
secrets and bricks it. Sophisticated attackers could detect Trick
PINs that continue operation (duress PINs), unlike the average thug.


## Fast Brick

Quickly bricking the system is done by rotating the SE1
pairing secret by mixing in a random nonce via the chip's key
rotation process. Only a knowledge of the old pairing secret is
needed for this change. This is similar the to `brick_me` PIN
and how that worked on previous products.

