# Dual Secure Elements

## Background

The Mk4 COLDCARD has two secure elements. Each is made by a different vendor,
so we know they will have different bugs and weaknesses.

SE1 = ATECC608B from Microchip
SE2 = DS28C36B from Maxim

SE1 is the same part used on Mk3 but we are using it a little differently, while
SE2 is completely new chip we haven't deployed before. Both use SECP256R1
for Elliptic-curve Cryptography (ECC) and HMAC-SHA256.

## Design Goals

There are 3 parties here which hold secrets: the main MCU
(microcontroler), and the two secure elements. Our goal is that
**all three** must be fully compromised to access the seed phrase.
Thus if a vulnerability is identified in one of the parts, the
COLDCARD as a whole is still secure. Additionally, knowledge of the
correct PIN code will be required, even if all three devices have
been cracked wide open. (But this is a last line of defense, and a
brute force attack on all PIN combinations will breach it).

We assume our attackers have physical access to your COLDCARD, have
cracked open the case, and can probe on the bus connections between
MCU and SE1 or SE. Attackers may even have desoldered the SE1 and
SE2 from the board, and put active circuits between them and the
MCU (an active MiTM attack). [Even so, on the Mk4, we have improved
the goop on all three parts and all these critical signals run on
internal layers of the PCB.]

The Mk4 will also support new "trick PIN" codes that will have side
effects such as wiping or bricking the COLDCARD or providing access
to a decoy or duress wallet. Ideally, attackers will not be able
to detect such a false PIN was given, even while probing the signals
on the board.

## MCU vs. SE1 and SE2

As in Mk1 through Mk3 of the COLDCARD, the MCU has a "pairing secret"
which is used to authenticate itself with SE1 and vice versa. This
pairing secret (32 bytes) is held in flash memory in a protected
area. Only the boot loader code can access this memory, and the
micropython code cannot read this area of the chip. We use an internal
"firewall" feature and PCROP (Proprietary code readout protection) to
acheive this.

In Mk4, we will also have a shared secret between the SE2 and MCU.
Just like SE1, this is used to authenticate the SE with MCU and to
encrypt their mutal communications. The pairing secret for SE2
will not be stored in SE1 and is unique from the other pairing
secret used for SE1.

Probing on the electrical connections between the SE1 or SE2 and
MCU is secured by way of these pairing secrets. In practise this
means most commands and responses are XOR'ed with an HMAC-SHA256
value where the HMAC key is the pairing secret and the message is
a hash of the command arguments.

There are also some cases where an ECC signature and ECDH are used
to establish a shared secret between devices.

## Seed Decryption

SE1 will still hold your seed phrase, but that phrase is encrypted
by AES and SE1 does not contain a key to decrypt it. The key to
decrypt that is stored in the MCU and SE2. To access the AES key
held in SE2, you need SE1 to perform a public key signature and
ECDH setup which in turn requires the main PIN code. Of course the
MCU will only provide its key if both SE1 and SE2 are satisfied.

In earlier COLDCARD versions, we XOR'ed the stored value with a
secret in the micro (one time pad), but the new approach is more
powerful because we are mixing in values from the SE2 and MCU using AES.

This gives much more flexibility and resistance to known plaintext
attacks.

## All The Keys

| Symbol        | Chip's Name | Type | Holder   | Purpose
|---------------|-------------|------|----------|----------
| SE1 pairing   | slot 1      | HMAC | SE1, MCU | Protects communications between SE1 and MCU
| SE2 pairing   | secret A    | HMAC | SE2, MCU | Pairing for SE2
| SE2 comms     | keypair A   | ECC  | SE2      | MCU captures pubkey half, used in ECDH comms
| SE joiner     | slot 7, pubkey C    | ECC  | SE1/SE2  | SE2 knows only public part, SE1 has privkey
| pin stretch   | slot 2      | HMAC | SE1      | key stretching for PIN entry and anti-phish words
| firmware      | slot 14     | SHA256d | SE1      | firmware checksum, controls green/red light
| nonce/chksum | slot 10    | data | SE1        | AES Nonce and GMAC tag, protected by PIN
| MCU seed key  | tbd         | AES  | MCU      | MCU's contribution to AES protecting seed
| SE2 easy key  | page 15    | AES via HMAC  | SE2      | Another SE2 part of AES seed key; easy to wipe for self-blanking features
| SE2 hard key  | page 14    | AES via ECC  | SE2      | SE2's part of AES seed key; ECC used to unlock
| tpin key      | MCU       | HMAC(key) | MCU   | key for HMAC used to encrypt trick PINs
| MCU pin check | tbd         | HMAC | MCU      | Used as HMAC key using hashed PIN as msg
| trick PIN slots | pages 0-12 | HMAC | SE2     | Protect duress wallet seeds and pins (6 spots)
| SE2 trash     | secret B    | HMAC | SE2      | used to destroy values (only SE2 knows the value)
| hash cache secret | -       | XOR/AES | MCU   | in-memory encryption of actual PIN when unlocked
| mcu hmac key     | -           | HMAC | MCU | used as hmac key to compress other keys
| replacable mcu key       | MCU       | AES | MCU    | replacable MCU key (up to 32 times)

All keys above are 32 bytes long and picked randomly using the hardware RNG.

When a PIN code is entered, it gets hashed by the same process as
in previous COLDCARD versions. This is quite involved, and uses a value in SE1 for key
stretching purposes. The final hashed PIN value, would unlock a few
slots from SE1, but first, the a hashed value is HMAC'ed using "MCU
pin check" and that hashed PIN value is used to check for trick
PINs which are stored in SE2. If none of the trick PIN's are decoded
in SE2 memory, then we will try the PIN for real against SE1.

If the PIN is correct, then the pin-attempt counter is reset to 13
tries, and the "SE joiner" slot on SE1 is used to establish ECDH
communication between the MCU and SE1, and to authorize a specific
page on SE2 that holds "SE2 seed key". That value, the seed phrase
from SE1 (unlocked by correct PIN) and the "MCU seed key" can now
be used to decrypt the seed phrase.

Final seed decryption key is combined from all these sources:

k = HMAC-SHA256(key=(mcu hmac key), msg=(SE2 easy key + SE2 hard key + current replacable mcu key))

### AES Details

We are using AES-256 in
[CTR mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)).
For message authentication, we add 32 bytes of zeros past the
end of the message and check those decode correctly.

A new keyslot (10) is used to store this MAC data, which is simply zeros, encrypted.

A single fixed random value is used for nonce (IV), composed of the
first 15 bytes of the "mcu hmac key", followed by a zero (counts
up from there if more than 16 bytes are being en/decrypted).

### MCU keys

Two keys are stored in the MCU that affect the seed.

"mcu hmac key" is fixed at factory setup time. It acts as the "key" for
an HMAC operation that compresses the seed key.

"replacable mcu keys" are picked at runtime and saved to flash.
There is only one active at a time, but we have a few slots in flash for
new ones.  When the COLDCARD "wipes" itself, it is clearing the
current MCU replaceable key. That process is very fast, and does
not have any external signals to betray that it's occuring. There
is no need to clear the keys in SE2 or SE1, since without that the
MCU replacable key, the actual AES key is still unknown.

New COLDCARD's will ship from the factory with no key picked yet.
Once the main PIN is set, and a wallet imported or created, then
the first MCU replaceable secret will be picked.

Each "wipe" operation consumes a replacable key, and there is a limited
number of them available during the life of the COLDCARD.

### Captured values

For values that are public or semi-public, the MCU captures them and does
not allow them to change later. This includes:

- serial number for SE1 and SE2 chips (used in most HMAC responses, fully public)
- public key for: "SE joiner", and "SE2 comms" key pairs

Logically, these values could be read at runtime, but since they
are not expected to change, we store them and thus assure they do
not change when under attack, perhaps by substituting a different part.

We block these from read-back (out of the SE) where we can.

## Trick PIN's

To support specific COLDCARD features, we need to have a number of
distinct PIN codes that have various side effects, such as unlocking
a duress wallet, triggering a long login delay, bricking the COLDCARD,
or blanking it.

These PIN's will be stored in even-numbered pages of SE2. The
adjancent odd slot will hold the corresponding secret. The MCU will
try each PIN the user enters against all the slots, and will silently
do what is needed to support the trick features.  For duress wallets,
we will store 32 bytes of seed phrase (generated via BIP-85 from
the true seed). For the other cases, a short numeric code will be
encoded, and provided to higher layers for implementing. A flag in
that code can trigger the bootrom to wipe the "MCU seed key". Because
this change is internal to the MCU it cannot be interrupted or
monitored by external actors. Since it's just as critical as the
other parts of the AES key for the seed phrase, being zero will
make the seed completely inaccessible, forever.

The MCU code may continue to go through the motions of speaking to
SE1 to complete the fraud, but in general, we will not be storing
the duress wallet or brickme PIN on the SE1 any more. All those features
in Mk4 are implemented in SE2 now.

## Spare Slots

With trick pins moving to the SE2, we have some free space inside
SE1. We are calling this "spare secrets" and there are 3 x 72 bytes
worth of space. They are protected with all the same measures as
the main seed phrase.

The "long secret" (416 bytes) is still supported although its API
may have to change because fetching it in 32-byte blocks is very
slow since the primary AES seed key has be reconstruted for each
call.

## Observations

It's important that the SE2 cannot be used to validate a PIN code.
It does not have the rate limiting (or usage counter) that SE1 does,
so brute forcing would be easy. For this reason, only trick pins
are stored in SE2. Compromise of the MCU would be required to test
against those, and the max attempt rate would be 6ms (due to SE2
performance).  Doing that would be pointless, however, if you have
control over the MCU... you would just NOP-out the trick PIN checking.

If your attackers are smart enough to crack open case, and monitor
the buses involved, then you should provide a trick PIN that wipes
the secrets and bricks the COLDCARD. Trick pins that continue
operation (duress pins) will be detectable to those attackers, but
not your average thugs.



