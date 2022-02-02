# COLDCARD Mk4 Security Model

## Abstract

**COLDCARD<sup>&reg;</sup>** Marks 1 through 3 used a single secure element
to store a hardware wallet’s most important secrets: the 24 seed
words used to generate a deterministic wallet. This secure element
is in a limited and read-only state until authorized by PIN entry.

Clearing the secure element is impossible without first entering
the correct PIN. The Mark 4 COLDCARD (Mk4) introduces several new
security features, including a second secure element and Trick PINs
which can render stored data unrecoverable, or brick the COLDCARD
entirely if necessary, without entering the true authorization PIN
(True PIN).


## Introduction

Previous versions of the COLDCARD had a single secure element, first
the Microchip ATECC508A and later the ATECC608B, to store its
secrets. This secure element has 72 bytes of storage protected by
a 4- to 12-digit PIN code.

Mk4 adds a second secure element to the COLDCARD. The ATECC608B is
used still, and we call it SE1 (Secure Element 1) and and new chip
is SE2 (Secure Element 2): Maxim DS28C36B. The DS28C36B and has
more memory with, 15 32-byte slots of secure storage. SE1 and SE2
have different constraints and configurations to serve different
security roles. Some of SE2's slots authenticate SE1, while others
hold the new Trick PINs and their associated wallets.

The design goal for Mk4 is that both secure elements 1 and 2, and
the main MCU  need to be fully compromised before seed words are
leaked. It's no longer the case that an unanticipated issue with a
secure element's chip design can allow seed words to escape the
COLDCARD.

Another feature implemented in Mk4 is "Fast Wipe". It quickly clears
the contents of the two secure elements without entering the True
PIN. A limitation in Mk3 and previous versions was that interaction
with the secure element required authentication. The secure element
was very limited read-only; clearing stored data required the True
PIN.

Encrypting values inside the secure element began with Mk2. Mk4
distributes the encryption key among three components: the main
MCU, SE1 and SE2. The main MCU now can clear its part of the
HMAC-SHA-256 key, making it impossible to decrypt the data held inside
SE1. Fast Wipe performs a simple write to the main MCU without
authentication data. This also allows Trick PIN configurations to
include functions like wiping the seed.

Learn more about the [mk4 dual secure elements.](mk4-secure-elements.md)

## Trick PINs Implementation

Mk4 introduces a new concept called "Trick PINs". These PIN codes
are any PIN other than the "True PIN", and the user configures them
to perform different functions in many different ways.

When a user sets a Trick PIN, SE2 records it with a few bytes of
flags and arguments. This may also include up to 64 bytes of seed
data. When a PIN is entered on a COLDCARD, the boot ROM checks all
the Trick PINs first. If the PIN entered matches a set Trick PIN,
the COLDCARD performs the trick.

Find the Trick PIN settings under:
_Settings > Login Settings > Trick PINS_


### Trick PIN Options

Using a Trick PIN can initiate one or more of the following options:

- Wipe the seed
- Mimic a blank device (appears to have wiped the seed)
- Load a duress wallet (2 types supported)
- Brick the COLDCARD immediately.
- Start a login countdown timer (may include wipe/brick)
- Pretend PIN is incorrect and perform additional tricks (such as wipe).
- Display wiped message on the screen (but don't actually do it)
- Just reboot the COLDCARD (no change to state)
- Delta Mode: advanced duress with real seed.
- You can trigger most types of tricks on ANY wrong PIN, in addition to specific values.

#### Hidden Tricks

Once defined, you may hide a trick PIN from the menu, so it is not
visible but still in effect. Should you need to change it, you
should pick "Add New Trick" and re-enter the trick PIN.  The COLDCARD
will "remember" the Trick PIN and restore it to the menu.

#### Duress Wallets

Entering a trick pin that leads to a duress wallet operates as if
the correct PIN was provided. However, the attacker will not stealing
your main stash.

The private key can be automatically derived using BIP-85 methods,
based on account number 1001, 1002, or 1003.  Because this is BIP-85
based and uses 24-word seed it behaves exactly like a normal wallet. You
can even define a passphrase on top of that.

To support older COLDCARD duress wallets and their UTXO on the blockchain, you can
also create a compatible wallet easily.

#### Brick Self

A trick PIN can be used to brick (destroy) the COLDCARD.

The brick effect is immediate and shown to the user as a "Bricked."
screen. Subsequent reboots will also show "Bricked." and the COLDCARD
is now e-waste.

#### Wiping Seed

A trick PIN can be used to wipe (forget your seed).  After wiping
you can choose to:

- reboot with no message
- be silent and pretend the PIN code was wrong
- proceed to a duress wallet
- show a message saying seed is wiped, stop


#### Look Blank

Pretend we are a wiped COLDCARD, but don't wipe anything.


#### Login Countdown

This wipes the seed, and then pretends a login countdown is needed.
At the end of the count down, you can config the COLDCARD to brick
itself or just reset.

#### Delta Mode

Delta Mode is the most advanced option and is not recommended for
use by novices. This function is inspired by safes that allow the
addition of one digit to the final number to act as a duress code.
The safe will open, but a silent alarm is triggered (or poison gas
is released). Delta Mode is activated by a Trick PIN that must
differ from your True PIN by only the last four digits.

Delta Mode will log into the secrets in SE1 using your True PIN
code which is calculated from the Trick PIN and the contents of
SE2.  Nothing unusual can be detected externally; the COLDCARD
behaves normally and it does have access to your actual seed words.
However, internally, the COLDCARD operates in a special mode.

In "Delta Mode", attempting to view the seed words wipes the seed.
Anything that could reveal the seed words, like accessing the Trick
PIN menu to determine if a trick is in effect will wipe the seed.
But if these menu functions are avoided, a user (the attacker) could
sign transactions in Delta Mode.

Transactions signed in Delta Mode do not have correct signatures
so if the signed transaction is broadcast, it will be rejected by
the network because the signatures do not verify.

The value of Delta Mode is against a well-researched attacker who
knows the XPUB or XFP of your true wallet. This could be learned
from an Electrum wallet file being discovered on your personal
computers, with a massive balance---obviously you control that
wallet.  The UTXO which you are controlling are known, so providing
a duress wallet won't be good enough. In delta mode, it appears the
attacker has control over the right XPUB/XPRV and UTXO.

## Other Mk4 Security-Related Improvements

In addition to adding a new secure element in Mk4, COLDCARD gains
several other security improvements.

### Countdown to Login Feature

This feature can be configured to incorporate Fast Wipe on the Mk4.
Because it is implemented as a Trick PIN is gains protection residing
inside SE2.

The login delay is no longer continued after a power cycle. The
delay, which can be up to 28 days long, begins again from zero after
a power failure.  Since this policy change can only increase the
waiting time, it seems prudent and was suggested by our customers.


### Kill Key Feature

This feature allows the user to execute a Fast Wipe when the
anti-phishing words are displayed on the screen. This feature is
turned off by default.

The user sets a particular key number to trigger Fast Wipe. If that
key is pressed while viewing the anti-phishing words, the seed is
wiped immediately, and the login process continues. Nothing is shown
to indicate the seed has been wiped.

It is strongly recommended that the first digit of the second half
of the True PIN is **not** used as the Kill Key. Missing a step
would unintentionally wipe the seed.

### SPI Serial Flash Removed

The Mk3 and earlier had a dedicated, external chip which held
settings and the PSBT during operation.  That chip is entirely
removed in Mk4. The settings now reside inside the main MCU,
increasing security. Settings are still AES-encrypted as before.

The separate settings chip could be blanked externally or even
removed/replaced. This might enable getting around security features
that were not part of the secure element. Although the risk of that
is not significant, Mk4 eliminates that risk entirely.

In addition, the PSBT file now is held in an 8 MB pseudo-SRAM (PSRAM)
chip during operation. It is word-addressed, not page-based, and
there is nothing to erase. This makes signing transactions much
faster and permits transaction sizes up to 1 MB (the network only
accepts transactions up to 100 KB). This removes previous transaction
size limits.


### Virtual Debug Serial Port Removed

Mk3 and earlier made a virtual serial port available over USB. As
it was only useful to developers, it was disabled by default. Mk4
uses a real universal asynchronous receiver-transmitter (UART)
leading to physical pins. It is not only disabled by default, but
it also cannot be accessed without breaking the case. A developer
wanting to interact with the pins must be willing to damage the
COLDCARD's case to do so, but the option is there if needed.

---

**seems I was repeating myself; I'd already documented this SE1/2 stuff better**

## SE1 and SE2 Binding, or Key Distribution

> You'd decide section naming later

Achieving the security goals of Mk4 required tying a single key into three components. The main MCU, SE1, and SE2 would have to be broken where the contents can be read bit for bit to extract the seed words. Seed word protection is core to our mission.

SE1 holds the True PIN, as in previous Marks, and it holds up to 72 bytes of the AES-encrypted secret (seed words). The AES encryption is a product of the secret held by the main MCU, a secret held by SE1 and a secret held by SE2.


### Background: SE1 Architecture and Slot Usage

SE1 is a Microchip ATECC608B. It has 15 key slots that can be purposed for keys, certificates, or data. One 72-byte area holds the main secret. Another area of 400 bytes of secure storage holds what we call the Long Secret (only used in the bunker).


### The Pairing Secret (SE1 and the MCU)

SE1 only talks to the main MCU if, and only if, it knows the Pairing Secret. The Pairing Secret is the secret shared between the main MCU and SE1. It is a 32-byte random number set by the factory the first time a COLDCARD powers up.

Cracking the main MCU and reading the boot ROM &mdash; which is deliberately difficult to read out &mdash; would make it possible to send commands to SE1, but not view its secret slots. Accessing the secret slots, like the one holding the AES-encrypted seed words, requires the Pairing Secret and the True PIN. The True PIN is hashed with secrets that are unique to each COLDCARD.

Providing both the True PIN and Pairing Secret allows interaction with another slot on SE1 holding the private key for joining SE1 and SE2.


### The Joiner Key (SE1 and SE2)

The Joiner Key joins SE1 and SE2. It's a 32-byte elliptic curve cryptography (EC) key on the secp256r1 curve, not the Bitcoin curve (secp256*k*1). The public part of the Joiner Key is saved in SE2 during setup. The private part of the Joiner Key is determined by the true random number generator (TRNG) inside SE1 and never leaves the chip.

Like the Pairing Secret, the Joiner Key is protected by the True PIN. Accessing the Joiner Key requires the True PIN, which means the PIN's hashing data from both the main MCU and SE1, and the Pairing Secret. Once these items are verified, the Joiner Key allows further operations.

### SE2's Hard Key

The Joiner Key unlocks SE2's Hard Secret. SE2 is essentially independent of the True PIN code, which is why SE2 stores the Trick PINs. SE2 does not hold the True PIN directly.

Unlocking SE2's Hard Secret involves a signed message. The True PIN authenticates SE1 to get a random nonce generated by SE2. SE1 signs the nonce with its private Joiner Key and returns the result to SE2. SE2 uses its public Joiner Key to authenticate the message. This produces the Hard Key for SE2, a 32-byte random key that doesn't change during the product's lifecycle.

SE1 provides the actual data, the AES-encrypted seed words. One of the keys in the main MCU generates the key for that encryption. The main MCU has about 100 slots to store random keys generated on the fly. Fast Wipe tells the main MCU to forget the current key and generate a new one. The secret will then be encrypted by the new key. Decrypting SE1's secrets will fail the checksum and the COLDCARD will behave like nothing has been set, zero data. The previous key no longer exists.  

Combining all these keys together takes time, making the Mk4 slower to read its secrets. The full process may take up to a full second to complete.


## SE2 Trick PIN Slots and Other Features

SE2 is a Maxim DS28C36B on its own I2C-bus connected to the main
MCU, operating independently in terms of connections. It is not
directly connected to SE1 and it does not have an LED indicator.
SE2 is primarily used for the Trick PINs, but it also holds one
part of the encryption key for the main secret. This part is the
Hard Slot.

When a PIN is entered, it is hashed through a series of operations that take a round trip to SE1. This is the same as the Mk3 using its secure element for key stretching. A 32-byte deterministic hash, dependent on secrets from the main MCU and SE1 and unique to each COLDCARD, is returned. The hash is compared against all 14 of the slots in SE2.

A few least significant bits (LSB) are masked out of the hash. If the PIN entered matches one of the slots, the masked-out bits are checked. Based on the check, two values are taken: `tc_arg` and `tc_flags`. These two values implement Trick PIN features.


### tc_arg and tc_flags

The flags are checked along with their corresponding arguments if a match is found while iterating through all the slots. Some flags are implemented directly in the boot ROM (factory-set, unchanged between releases, and is not field-upgradable) before anything is sent to MicroPython. Other flags are passed to MicroPython for implementation or are implemented in both the boot ROM and MicroPython.

**Example 1** A flag is set for Fast Wipe and an attacker has control of the IceGrid C-bus going to SE2 and the one-wire bus going to SE1. They can attempt to block the wipe in hopes of trying different PINs without damaging anything, but they will fail. If `tc_flags`, which is a bitmask, indicates a Fast Wipe, the seed wiping happens inside the main MCU. It clears data inside the main MCU extremely quickly and with no external signals &mdash; either before or after &mdash; to indicate it happened. This prevents blocking Fast Wipe.

**Example 2** The login countdown feature allows specifying a Trick PIN. When the Trick PIN is entered, the COLDCARD will show a countdown timer and the time that must elapse before logging in is allowed. `tc_arg` encodes the number of minutes on the delay.

**Example 3** Although SE2 holds the Trick PINs, it does not know the True PIN and Delta Mode will not reveal the full True PIN. The Trick PIN has its unique hash result, and an entry from SE1 is used to calculate the True PIN. This is accomplished by masking out the last four digits of the hash and substituting four digits from `tc_arg`. Limiting it to four digits enables a difference between the Delta PIN and the True PIN.

This makes the True PIN unknowable without the Trick PIN; SE2 cannot be searched for the True PIN and generating the PIN hashes for SE2 would only be possible after cracking SE1 and the main MCU.


## Main MCU Secrets

The main MCU holds secrets that are picked at run time, either in the factory or otherwise. For example, it shares secrets with SE1 (Pairing Secret) and SE2. These secrets do not change during the lifecycle of the device. In both cases, hash-based message authentication code (HMAC) is used to encrypt traffic on the bus. Communication can be monitored, but not understood. It will not yield any secrets or information due to the encryption.

The table of keys inside the main MCU begin as unprogrammed flash and the keys are generated on the fly. Each time a new seed is set up, a new key is picked and combined with the keys from SE1 and SE2 creating an AES-256-CTR (counter mode) key to encrypt the seed words. To generate that key, an attacker would have to compromise the main MCU, SE1 and SE2. Since the key component from the main MCU is disposable, it can be destroyed in microseconds or nanoseconds by Fast Wipe. One third of the original key for decrypting a COLDCARD's secrets is gone, and a random key now replaces it. The original seed cannot be decrypted without that original key component.

Fast Wipe eliminates the old key, programs the flash to 0 and picks a new random key. After the first Fast Wipe, one of the slots in the main MCU will be all zeroes, the next slot will be a random number, and the remaining slots will be all ones.


**NOTE: Public Keys in Main Micro**
> _"I think there's also some public keys in the main micro, just put a note there, I'll come back and write the other keys in."_

**NOTE: Tables for SE1, SE2, and Main Micro**
> _"For SE1 and SE1 there'll be a table which lists the actual details about each slot... ...I can put those in there later... ...There's 3 sections which need a table at the end."_


## Calculating the Seed-Protecting Encryption Key

Calculating the encryption key protecting the seed words requires data from all three components: the main MCU, SE1, and SE2. All encryption operations are implemented in the hardware. The Mk4 has a secure version of the main chip which implements SHA-256, AES, and HMAC natively; the boot ROM takes advantage of these capabilities.

SE1 provides the Easy Key, which requires the Pairing Secret stored in the main MCU. SE2 provides the Hard Key, which requires authentication on SE1 and the private key on SE1. Although it's called the SE2 Hard Key, it involves both SE2 and SE1. The main MCU provides the third part of the key, the throwaway key that can be destroyed by Fast Wipe.

These three 32-byte values are hashed using SHA-256. HMAC combines the result from the SHA-256 hash using another key in the main MCU, the MCU HMAC Key. The MCU HMAC Key has an over-message of 32&times;3 bytes which includes SE1's Hard Key and Easy Key. This goes into AES-256-CTR to decrypt the bytes stored in SE1.

Mk3 used one-time pad (OTP) encryption of the secret in the secure element. Mk 2 did not encrypt the secret in the secure element.

The complexity of the process raised performance concerns. Completing all the operations could take up to 5 seconds, so this is not done immediately upon logging in. The first time the master secret is required, the operations are performed, and the result is cached in RAM for about two minutes. Applying signatures within the same transaction will keep the result in memory, but the result is deleted immediately after, often before UI interaction is complete. Holding the results in RAM is a necessary compromise to prevent delays in signing transactions.

The 72-byte secret is decrypted along with 32 bytes of checksum. The checksum, which is 0 bytes but encrypted, acts as a message authentication code (MAC). The MAC is necessary in case Fast Wipe is implemented. Fast Wipe changes the AES key, so garbage is decrypted and the checksum does not match. But an incorrect checksum is not treated as an error, it is treated as zero data due to the MAC value. This ensures the COLDCARD will be seen as a blank device after Fast Wipe. Writing to save the seed words also saves an updated checksum, a MAC value of zeroes that are encrypted. The 72 bytes are not lost but stored in a new slot in SE1.

