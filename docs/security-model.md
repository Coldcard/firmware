# COLDCARD Mk4/Q Security Model

## Abstract

**COLDCARD<sup>&reg;</sup>** Marks 1 through 3 used a single secure
element to store a hardware wallet’s most important secret: the 24
seed words used to generate a deterministic wallet. This secure
element is in a limited and read-only state until authorized by PIN entry.

Clearing the secure element is impossible without first entering
the correct PIN. The Mk4 COLDCARD introduced several new security
features, including a second secure element and Trick PINs which
can render stored data unrecoverable, or brick the COLDCARD entirely
if necessary, without entering the true authorization PIN (True
PIN).

The COLDCARD Q continues with the same security model introduced
in Mk4.


## Introduction

Previous versions of the COLDCARD had a single secure element, first
the Microchip ATECC508A and later the ATECC608B, to store its
secrets. This secure element has 72 bytes of storage protected by
a 4- to 12-digit PIN code.

Mk4 adds a second secure element to the COLDCARD. The ATECC608 is
still used, now called SE1 (Secure Element 1), along with a new
chip, the Maxim DS28C36B, called SE2 (Secure Element 2).  The
DS28C36B (SE2) has more memory with fifteen 32-byte slots of secure
storage. The two chips have a cryptographic link requiring signed
challenges between them.

The design goal for Mk4 is that both secure elements 1 and 2, and
the main MCU need to be fully compromised before seed words are
leaked. It's no longer the case that an unanticipated issue with a
secure element's chip design can allow seed words to escape the
COLDCARD.

Encrypting values inside the secure element began with Mk2. Mk4
distributes the encryption key among three components: the main
MCU, SE1 and SE2. The main MCU now can clear its part of the
HMAC-SHA256 key, making it impossible to decrypt the data held inside
SE1. The Fast Wipe feature performs a simple write to the main MCU without
authentication data. This also allows Trick PIN configurations to
include functions like wiping the seed.

Learn more about the [Mk4's dual secure elements.](mk4-secure-elements.md)

## Trick PINs Implementation

Mk4 introduces a new concept called Trick PINs. These PIN codes
are any PIN other than the True PIN, and the user configures them
to perform different functions in many different ways.

When a user sets a Trick PIN, SE2 records it with a few bytes of
flags and arguments. This may also include up to 64 bytes of seed
data. When a PIN is entered on a COLDCARD, the boot ROM checks all
the Trick PINs first. If the PIN entered matches a set Trick PIN,
the COLDCARD performs the trick.

Find the Trick PIN settings under:
`Settings > Login Settings > Trick PINS`


### Trick PIN Options

Using a Trick PIN can initiate one or more of the following options:

- Wipe the seed
- Mimic a blank device (appears to have wiped the seed)
- Load a duress wallet (two types supported)
- Brick the COLDCARD immediately
- Start a login countdown timer (may include wipe/brick)
- Pretend PIN is incorrect and perform additional tricks (e.g. wipe)
- Display wiped message on the screen (nothing is actually wiped)
- Reboot the COLDCARD (no change to state)
- Delta Mode: advanced duress option with real seed

ANY wrong PIN can trigger most types of tricks, as can specific values.


#### Hidden Tricks

Once defined, you may hide a Trick PIN from the menu. The Trick PIN
won't appear in the menu despite being set. To change it later, select
`Add New Trick` and re-enter the Trick PIN.  The COLDCARD will
restore the Trick PIN to the menu.


#### Duress Wallets

This Trick PIN leads to a duress wallet that operates as if the
user entered the True PIN. An attacker will only have access to the
duress wallet. They won't have access to steal the main stash.

The private key can be automatically derived using BIP-85 methods,
based on account numbers 1001, 1002, or 1003. Because this is BIP-85
based and uses a 24-word seed, it behaves exactly like a normal
wallet. Defining a passphrase for the wallet is also possible.

The Mk4 also supports older COLDCARD duress wallets and their UTXOs
on the blockchain. There is an option to create compatible wallets
easily.


#### Brick Self

A Trick PIN that bricks (destroys) the COLDCARD.

The brick effect happens immediately, and the screen displays
"Bricked." Subsequent reboots will also show "Bricked." The COLDCARD
is now e-waste.


#### Wipe Seed

Use a Trick PIN to wipe (forget) the COLDCARD's seed. After the
seed is wiped, a user can set the device to:

- Reboot with no message
- Be silent and pretend the PIN code was wrong
- Proceed to a duress wallet
- Show a message saying, "Seed is wiped, Stop"


#### Look Blank

The COLDCARD pretends it is blank, but it is not. All data remain intact.


#### Login Countdown

The COLDCARD wipes the seed and displays a login countdown. This
function has two options for the end of the countdown: the COLDCARD
will brick itself, or the COLDCARD will just reset.


#### Delta Mode

Delta Mode is the most advanced option, and it is not recommended
novices use it. This function is inspired by safes that allow adding
one digit to the final number to act as a duress code. The safe
will open, but a silent alarm is triggered (or poison gas is
released). A Delta Mode Trick PIN must differ from the True PIN,
but only by **the last four digits**.

Delta Mode logs into the secrets in SE1 using the True PIN code.
The COLDCARD calculates the True PIN using the Trick PIN and contents
of SE2. Nothing unusual can be detected externally; the COLDCARD
behaves normally and it has access to the actual seed words.
Internally, however, the COLDCARD operates in a special mode.

In Delta Mode, attempting to view the seed words wipes the seed.
Anything that could reveal the seed words, like accessing the Trick
PIN menu to determine if a trick is in effect will wipe the seed.
An attacker avoiding these menu functions could sign transactions
in Delta Mode.

Transactions signed in Delta Mode do not have correct signatures.
If the signed transaction is broadcast, the network will reject it
because the signatures do not verify.

The value of Delta Mode is against a well-researched attacker who
knows the XPUB or XFP of the true wallet which is their target. An
Electrum wallet file on a user's personal computer can provide these
identifiers to an attacker. The computer's owner obviously controls
that wallet and its temptingly massive balance. Since the user's
UTXOs are known; a duress wallet won't suffice. Delta Mode lets the
attacker believe they control the correct XPUB/XPRV and UTXOs.


## Other Mk4 Security-Related Improvements

In addition to adding a second secure element in Mk4, COLDCARD gains
several other security improvements.


### Countdown to Login Feature

The Mk4 adds a configuration option to incorporate Fast Wipe.
Implementing this feature as a Trick PIN keeps it protected inside SE2.

Also new in Mk4: the login delay starts over after a power cycle.
Up to 28 days long, the delay restarts from zero after losing power.
Increasing the waiting time is a prudent policy change that our
customers suggested.


### Kill Key Feature

On the Mk4, this feature allows the user to execute a Fast Wipe
when the anti-phishing words are displayed on the screen. This
feature is turned off by default.

The user sets a particular key number to trigger Fast Wipe. If that
key is pressed while viewing the anti-phishing words, the seed is
wiped immediately, and the login process continues. Nothing is shown
to indicate the seed has been wiped.

It is strongly recommended that the first digit for the second half
of the True PIN is **not** used as the Kill Key. Missing a step
would unintentionally wipe the seed.

For the COLDCARD Q, the same feature exists: any letter may be
specified but numbers are not supported. This change allows the
"kill button" to be active through-out the entire login process.
It can be even be pressed while the nickname is shown, and at any
point during the PIN entry.


### SPI Serial Flash Removed

The Mk3 and earlier had a dedicated, external chip to hold settings
and the PSBT during operation.  Mk4 and later, do not have that
chip. The settings now reside inside the main MCU, increasing
security. Settings are still AES-encrypted as before.

The separate settings chip could be blanked externally or even
removed/replaced. This possibility might enable getting around
security features that were not part of the secure element. Although
it is not significant risk, Mk4 eliminates that risk entirely.

In addition, the PSBT file now is held in an 8 MB pseudo-SRAM (PSRAM)
chip during operation. It is word-addressed, not page-based, and
there is nothing to erase. This change makes signing transactions
much faster and permits transaction sizes up to 1 MB (the network
only accepts transactions up to 100 KB). Previous transaction size
limits no longer apply.


### Virtual Debug Serial Port Removed

Mk3 and earlier made a virtual serial port available over USB. As
it was only useful to developers, it was disabled by default. Mk4
uses a real universal asynchronous receiver-transmitter (UART)
leading to physical pins. It is not only disabled by default, but
it also cannot be accessed without breaking the case. A developer
wanting to interact with the pins must be willing to damage the
COLDCARD's case to do so, but the option is there if needed.


## SD Card Recovery Mode

Mk4/Q bootloader is smart enough to be able to read an SD card. You
will only be able to trigger the SD card loading code, if the
COLDCARD was powered down during the upgrade process. At that point,
the intended firmware image has been lost because it it held in
PSRAM only, during the flash writing process. The bootloader knows
main flash (ie. Micropython code) is corrupt because it fails the
checksum check (and/or signature check).

The bootloader will only install an image of exactly the same version
as was being installed when interrupted. This is done by verifying
the checksum of the proposed firmware vs. a value held in SE1. The
new firmware's expected checksum is recorded before any flash is
erased.

The SD card will be searched for all DFU files, and each is
checked for valid factory signature, and that its checksum matches
the anticipated version the user was attempting to install.

If any other parts of flash---beyond the normal upgradable firmware
area---have also been corrupted, this process will not work and the
unit will be a brick.

On the COLDCARD Q, only the top slot (A) is supported for this
operation.


## Flash ECC (Error Detection/Correction Codes)

Flash memory cells in this MCU are protected by ECC bits. An
additional 8 bits are calculated and stored alongside each 64-bit
value. This allows detecting any 2-bits changing and correction of
up to 1-bit error per 64 bits.

When a corrupted flash memory word is detected, an NMI (non maskable
interrupt) is caused which will crash the microprocessor. This
typically happens during boot-up when the checksum over flash memory
is performed.

We know of no legitimate way for this to occur, so we will assume
that it's an attack, such as exposing the bare die to targeted UV-C
radiation.  If the attacker is able to flip 2 or more bits, then
this will effectively brick the COLDCARD once the ECC error is detected.

Critical flash cells, such as those that prevent JTAG access, are
not a single bit (it's a special bit pattern), and regardless are
protected via ECC the same as other flash cells.

