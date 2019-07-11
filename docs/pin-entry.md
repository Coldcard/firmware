# Coldcard PIN Design and Operation

## What happens when I enter a PIN?

1) Enter between 2 and 6 digits of your PIN code prefix and press OK (checkmark).

2) The Coldcard will use those digits to find two specific words from the BIP39
word list. This two word response is unique to your Coldcard and pin combination.

3) Look at the words. Are they right and what you expected? If not,
press X and try again, and/or talk to your
["evil maid" about her activities](https://en.wikipedia.org/wiki/Rootkit#bootkit).
Do not continue to enter more digits of your real PIN!

4) If you want to proceed, and you have a secondary wallet enabled, press (2) to select
   the secondary wallet, otherwise, just press OK to continue for primary wallet (1).

5) Then enter the remaining digits of the PIN (between 2 and 6 digits). Press OK.

6) Is it the user-defined "brick me" PIN? If so, it's used to wipe
    the secure element and **irreversibly brick** the Coldcard immediately. There is no
    delay, even if failed PIN attempts are recorded. The pairing secret is rolled
    with a forgotten value, so it's impossible to ever talk to the secure element
    again. *(Before enabling this feature, please triple-check your backups are correct!)*

7) Calculate the required delay to punish previous incorrect PIN
    attempts. The current "attempt counter" for the target wallet (1)
    or (2) is observed, and the difference between that counter's current
    value, and the recorded "last successful attempt level" is used. If
    there has been an incorrect attempt previously, then make the user
    wait some time here.

8) After the delay, check the PIN. The PIN is checked in this order:

    - Is it the PIN for the duress wallet? If so, open that wallet and continue as if it
        was was the normal (1) or (2) wallet that was picked in step 4.

    - Otherwise, we increment the PIN attempt counter for indicated wallet at this point.

    - Check if the PIN is right. If it is, use that PIN to record the PIN attempt
      counter's new value (typically +1), and read out the encrypted secret.
      System is open.

    - If the PIN is wrong, tell them and start over.

## Notes

- it's possible to use the same PIN for both main/secondary wallets
- wrong pin attempts on secondary will not count against primary wallet, etc
- we can only support two seeds (full wallets) because the chip has only two
  counters for PIN attempt tracking
- we could wipe the device when too many PIN attempt happen, but we can't
  recover it as a blank/reusable device due to the security design.
- there is a separate independent duress wallet available for both wallet (1) and (2)
- there is no attempt limit/rate limiting for duress PIN's, but since the same
    (incorrect) pin is attempted on the real wallet, that attempt counter is
    effectively used to protect the duress PIN as well.


# Dark Duress Thoughts

If you are relying on the duress PIN, you should probably have a
brick-me PIN as well.

Very smart attackers could monitor the data bus between main micro
and the secure element.

When the duress password succeeds, activity on the bus would be
clearly different from the normal PIN. There is nothing we can do
about that because traffic analysis of the bus is not hard even
though the all sensitive data is encrypted.

However, on the screen, we will keep everything looking normal, and
in fact, we try hard not to reveal to the main firmware that the
duress PIN was used successfully.

So if there are wires connected to the Coldcard while you are being
forced to enter a PIN, then you probably use the brick-me PIN instead
of your duress PIN.

The attackers could tell when the brick-me PIN has worked, but when
the brick-me PIN works, the Coldcard will immediately use it to
destroy the main pairing secret. This renders the security element
useless. This happens in about 50 milliseconds and is done long before
before anyone gets an on-screen confirmation that it worked.

There is little time to interrupt this or jam the bus to stop it.
The system firmware always attempts the brick-me PIN before checking
the PIN is correct for duress or normal usage.

But really, you should rethink your life choices before getting
into these situations!

## Secret Keystrokes vs. Special PIN Codes

We considered various "secret" key-presses to trigger the duress or brick features.

But this approach doesn't work because:

- There is an Internet, and we have to document these features on it.
- You might not be able to directly touch the subject Coldcard at the critical moment.
- You might be forced to give a PIN code via phone or text message
- You can write down a duress or brickme PIN in places where it might be found by
  bad actors, but you can't trick someone into pressing an undocumented key at a
  specific time.
- Special PIN codes are fully configurable for the same reason: we can't make 666-666
  do something special if a quick Google tells anyone that's a trap.


## Where is the PIN stored?

All PINs are stored inside the secure element. The firmware does
not know the PIN until you enter it, and then it checks it is right
using the secure element, and may load the wallet seed if it works.

To be able to read the secrets (ie. wallet seed) out of the secure
element, the PIN is required. In fact, you have to hash the PIN
with a random number (nonce) generated by the secure element. This is
the main protection against replay attacks, and monitoring the bus passively.

Furthermore:

- you cannot separate the secure element from main micro, and then brute-force the PIN.
- monitoring the connection to the secure element does not reveal the PIN (or any protected secrets)
- there is no way to read (or change) the wallet seed without the PIN
- there is no way to change the PIN without knowing the old PIN
- there is no way to directly read the PIN
- PIN attempt counters cannot be reversed or reset, ever
- only actual, correct knowledge of the PIN can update the "last successful" record (ie. mark PIN attempt as successful)
- the main wallet PIN is required to update the flash contents and keep the genuine light green

All of the above claims are enforced by the secure element itself. The
only policy that is enforced by our firmware is the PIN attempt
timeout periods. The code that does that is in a specially restricted
area we call "the bootloader". It cannot be changed in the field.

All interactions with the secure element are authenticated themselves
with something we call the pairing secret. Thus, to test a PIN
value, you need that pairing secret. Only the boot loader knows the
pairing secret, so it is able to enforce rate limiting and other
policy choices.

## But I forgot my PIN...

Sorry, there is nothing we can do. Without knowledge of the PIN,
it's impossible to read out any of the secrets of the secure element.
That's true even if you knew the pairing secret and could talk
directly to the chip. Even if you knew every byte of the main flash
(and you do, it's open source software). Even if you desoldered the
secure element and attacked it with a supercomputer.

The only downside to this design is the legitimate customers who
have forgotten their PIN, and tragically have also lost their seed
backup. The firmware will force them into ever-longer delay cycles
between attempts, but they are free to spend the rest of their lives
attempting to find the right PIN.

It's not possible for us to wipe the device and start again as fresh
device. We cannot write the wallet seed stored in the secure element
without the previous PIN.


## PIN to Secret Value (hashing)

The low-level bootloader firmware supports PIN's of any length up
to 32 characters.  We recommend splitting that evenly between the
prefix and final parts, and we will force you provide a minimum of
two digits as prefix for the anti-phishing feature to work well. Due
to the numeric keypad, we have to limit PINs to numeric digits.

Internally, the characters in the PIN are hashed as follows:

    SHA256( SHA256( pairing_secret + purpose_salt + pin_digits ))

Where:
- `pairing_secret` is 32-byte secret kept by the boot loader
- `purpose_salt` is 4-byte value linked to the usage of the PIN (ie. for prefix vs. real pin)
- `pin_digits` ascii digits, or could be any octets for custom solutions.

This double-hashed value is what's stored inside the secure element
(32 bytes).  It cannot be read back out, and when it's written
(which requires proving knowledge of previous PIN), it is encrypted
as it travels on the bus. Because of the inclusion of the pairing
secret, the hashes generated by each Coldcard will be different.

## Genuine vs. Caution Lights

The green light will be lit **only** if the entire flash memory contents
are unchanged since the last time you logged in with the main PIN.
This is enforced cryptographically by the secure element which
is the only way to change the light because the signals for the light
connect exclusively to the secure element and are not connected to
the main microprocessor.

Every time when the system starts, the entire flash is hashed using
double-SHA256. The pairing secret is part of that, as is every
single byte of flash in the chip so it will be unique per-device.
The expected value of that hash is not stored except in the secure
element. The bootloader writes whatever it calculates into the secure
element and the secure element will only turn on the light
if it matches the expected value.

There is no way to read out what the hash is supposed to be, and
no way to change the state of the green/red lights without that
hash (and the pairing secret). The red and green lights are directly
connected to the secure element chip, and do not interact with the main
micro.

When the user upgrades the firmware, they can use the main PIN code
to capture the updated hash value into the secure element.

### Code Signatures

The bootloader will not run the main firmware if it
is unsigned or signed incorrectly. This means only Coinkite Inc.
can produce firmware that will run on this platform. We are open
to suggestions on how we could safely allow third parties to write
software that can be run on the device. Here are some of the
approached we considered:

-  a "red PCB" version of the hardware that looks different (and
therefore cannot be used as a doppelgänger) but does not enforce
the firmware signing policy.

- the user can opt into a particular key (from a another vendor
or their own key if they are a developer). The main PIN would be
required to do the opt-in, and it would probably be a one-way trip.

- some sort of centralized service that signs binaries if we trust
your team---a walled garden. (Considered a hopeless approach, but
in our list regardless.)

Regardless of the code signing policies, we want the the genuine/caution
feature to work and be a useful defense against maids.

We want everyone to be able to experiment on our platform, and
their coins are just as precious to them, as Bitcoin are to us.

### Production vs. Development Key

What we've done to satisfy these needs is as follows:

- the bootloader knows and trusts five public keys
- main firmware code is always checksumed and needs a correct signature
- (the private part of) key zero has been published on Github as part of the source tree.
- keys 1 through 4 are factory keys we will keep secret.
- official releases are using key 1 for now, but
  all keys other than zero are considered "official"

Experimental code, written by anyone, can be signed with key zero,
and the bootloader will accept it. However, if the genuine light
is red, it will show a scary notice to the user during boot time,
and enforce a delay of 25 seconds. If the main PIN
is used to "bless the firmware", meaning the light is green during
boot, the warning message is **not** shown, and bootup proceeds
as normal.

Here's what the warning screen looks like:

![dev-warning screen](dev-warning.png)


## How To Develop Professional Code on Coldcard

- Hire and pay a dev to write the changes
- Dev signs binary release with private zero key published in our Github
- Give firmware binary file to users (via web download probably)
- They upgrade via normal process (copy to microsd, or USB upgrade)
- On first reboot, big "unauthorized firmware" warning is shown, with delay
- If they know the main PIN (since they are the owner), they follow process to set green light
- Next reboot and following, as long as "genuine" mode is maintained, they boot without warnings

### Benefits

- no warnings, but still trustable thanks to ATECC508a
- random devs can replace 99% of firmware at micropython layer
- but they need to retain our code for talking to bootloader and 508a,
  so that PIN can be entered and verified
- all PIN related policy is enforced by unchangeable bootloader code, per this document

### Limitation

- if new device is intercepted from our factory (ie. without a main pin set),
  anyone could put any code onto it, and it would boot exactly like a real factory-direct unit
- that's why we need the serialized, tamper-evident bag
- flip side of this limitation: altcoiners can ship a modified version of our
  product that boots and runs normally when their customer first gets it.

### Obvious Hack-Attack

Idea: Find or steal a Coldcard. Load your trojan firmware onto it. Profit.

- but you don't know the main PIN (or else you'd have already stolen the funds)
- so changing the firmware is not easy since it does little without the main PIN: you
  will have to crack the welded case, and do some difficult soldering.
- regardless, once you change the firmware, red caution light will show
- since you can't set the genuine light without the PIN, and your trojan is signed
  with key zero, when the victim gets back,
  they will see the big "unauthorized firmware" warning, plus the red light and probably
  some scratches on the case, etc.
- weak solution: "helpfully" power up the coldcard for them, and say... "Here it
  is ready for your pin, sir. No idea why the light is red today."
- so we need to warn users to power up the Coldcard themselves every time they enter the PIN.

## Four Types of wallets, one Coldcard

The Coldcard effectively supports four independent wallets:
primary (main), secondary, main duress, secondary duress.

The secondary wallet is a little less capable than the main one,
since the main PIN is needed for changing certain configuration
values, and enabling the Genuine light. However, the secondary
wallet has the same secret protection, PIN retry counters and so on.

The intention is that main and secondary wallets are completely
independent of each other, in terms of funds and wallet seeds.

### Duress Wallets

Duress wallets could store any 72-byte secret, and it's as well
protected as the main/secondary secrets, but we only enable use of
the duress wallet when attempting access to the corresponding
main/secondary wallet. The PIN failure and retry delays are linked
together. We also hide the fact that the duress wallet PIN was used
successfully. These lies are promoted by the boot rom code---to
higher levels of software, operation proceeds normally.

When creating the duress wallet, Coldcard derives the wallet root
from the real wallet by a one-way process. This means when you
backup the main wallet, you are also backing up the corresponding
duress wallet and its give-away funds. Writing down the main
wallet's seed words will include the duress wallet and its funds.

The duress wallet operates like any other wallet on the Coldcard.
Load value and sign transactions as normal. By design, it acts just
like a normal wallet (either main or secondary). As part of your
preparations for a bad day when you need it, you should load it
with some funds after setup.


### Recovery of Funds from Duress Wallet

To recover funds from the "duress wallet", import your original seed
words into a new Coldcard, and assign a duress PIN again. Then login
to the duress wallet and re-import that into your desktop wallet.

Alternatively, if you have the 7Z encrypted backup file, decrypt
that and import the xprv shown inside for the duress wallet. You
could also calculate the extended private key based on the seed or
xprv of the real wallet.  We use BIP32 subkey paths to derive the
duress wallet, if `m` was your real wallet, the duress wallet will
be found at:

    m/2147431408'/0'/0'

Where:

    2147431408 = 0x80000000 - 0xCC10



## Problems with changing PIN codes on Duress Wallets

We want users (and thugs) who are logged-in with the duress PIN to
experience a complete wallet experience. However, there are some
problems when they start to change PIN codes like a normal user would.
If they try to change the main PIN code, we can detect that and change
the "duress" PIN code instead. To them, it looks like the main PIN
was changed successfully. However, if they try to change the duress
PIN code, then we cannot allow that to work. For one thing, we have nowhere
to store the new PIN code, nor a fake wallet to give them if
they tried to use it. For this reason, if they login with the duress
PIN, we always pretend like there is a duress wallet enabled already.

To change the duress PIN, requires the previous duress PIN, and we
show the same error as if they entered the wrong old PIN.

If you are somehow facing an attacker who is willing to verify he
has the real main PIN, it's possible that careful analysis of system
responses will imply he's working with the duress PIN. (If you
discover any sequences that reveal this easily, please tell us and
we'll see if we can cover them up better.)

If this is a scenario that concerns you, you may be asked what the
actual duress PIN is, while under duress. We suggest providing the
"brickme" PIN in that case. Alternatively, you can say you set the
duress PIN once, but have since forgotten it.

A related problem: if the duress PIN counts as a failure on the
real PIN, it would be obvious when it's used. Therefore, we cannot
bump the counters unless we know the PIN isn't the duress PIN.

Known limitation:

- When you login with the duress PIN, the real PIN failure counter
cannot (and should not be) reset. We suppress display of that count
if we know the duress PIN was recently used.

## Anti-Phishing Feature

We ask the user for a number of prefix digits from their PIN.
In response, two words are shown. How do we get those words?

The string of prefix digits is hashed (using SHA256) and that digest is used
as the message to be authenticated by a standard HMAC/SHA256 operation
as defined by
[FIPS-198-1](https://csrc.nist.gov/csrc/media/publications/fips/198/1/final/documents/fips-198-1_final.pdf). The HMAC/SHA256 key is contained in the
[secure element](https://www.microchip.com/wwwproducts/en/ATECC508A) and it
performs the HMAC operation.

The 256-bit key for this HMAC is known only to that specific chip
and doesn't exist anywhere else.

The 22 bits of that HMAC result are converted into two words
from the BIP39 English wordlist. Because there are just two words
to remember, we hope our users can memorize those words and use
this a simple test that they are talking to their Coldcard, and not
a doppelgänger.

There are about 4 million (2^22) possible word combinations, and
so as long as your PIN prefix is kept secret, it should not be
possible to display the correct words.

If an attacker did know your PIN prefix, **and** had access to your
Coldcard wallet, they could enter the prefix and note the words
displayed. From there, they could make a replacement Coldcard that
captures the remaining digits, after displaying the correct two
words. However, if the victim tries a few different PIN prefixes,
they can protect themselves (limited only by their mental storage
capacity for random words). You don't even have to use your real
PIN prefix for testing against phishing... you can enter and cancel
as many attempts before proceeding with your real PIN. (Personally, I plan to
search until I find a memorable pair of words, like "angle burger"
or "lazy goose").

As for exhaustive attacks, where all possible PIN prefixes from a
particular subject Coldcard are to be captured, the bootloader
implements some simple rate-limiting to limit the rate of extracting
the words, and the attacker must work through that interface, since
pairing secret is unknown. All of the results would need to be
stored on-device if they tried to be exhaustive, but assuming a
weaker 4-digit PIN prefix, that's only 30k of data. If this type
of attack is your concern, we suggest using the longest possible
PIN prefix.

We are rate-limiting this as follows: 150ms response time for first
10 values, then 2.5 seconds each for the next 15 (up to 25).  At
25 tries, we crash the system and a power cycle will be required
to continue. With about 9,999 combinations to cover all 4-digit
prefixes, it would take between least 10 hours to generate all
4-digit prefixes. To achieve that, you would have to write custom
firmware and get it onto the device. Any successful login resets
the rate limiting, so normal users will never see the impact of
this limiting.

# How It Works

We've made some bold claims above. How can you be sure we implemented it
as described?

First, please learn more about the secure element: the
[Microchip ATECC508A](https://www.microchip.com/wwwproducts/en/ATECC508A)
The full datasheet recently has been made public after being under NDA for
years. To get further into our design, you will need to understand the chip's
capabilities.

## Background

The 508a (Microchip ATECC508A) has 16 key slots. Each can be
configured in numerous ways. The chip has two two high-endurance
monotonic counters, which we use to track PIN attempts. Additionally,
it has OTP memory and general flash storage that we aren't using.
None of the Elliptic Curve features are being used in this project,
although we have used that on the [Opendime](https://opendime.com/) project.

The chip starts with a blank "configuration zone" which must be
fully defined and locked forever before using the chip. The policy
set in the configuration defines the relationships between the keys,
and what data is public or private.

See `stm32/bootloader/keylayout.py` to understand the contents of the
configuration zone. That code establishes this set of keys:

    pairing              1      Shared secret with bootloader code.
    words                2      Random value used for anti-phishing feature
    pin_1                3      PIN for main wallet
    pin_2                4      PIN for secondary wallet
    lastgood_1           5      Last successful login attempt (main PIN)
    lastgood_2           6      Last successful login attempt (secondary PIN)
    pin_3                7      Duress PIN for main wallet
    pin_4                8      Duress PIN for secondary wallet
    secret_1             9      Wallet seed (main): 72 bytes of ultra secrets
    secret_2             10     Wallet seed (secondary): 72 bytes of ultra secrets
    secret_3             11     Secret for duress (main)
    secret_4             12     Secret for duress (secondary)
    brickme              13     "Brickme" PIN storage
    firmware             14     Hash of flash contents, controls red/green light

Key slots zero and 15 are reserved because of chip limitations.

Each key slot (aka. data slot) can be restricted for reading, writing
and "authentication" by depending on another slot. So, for example,
the `secret_1` slot requires knowledge of the pairing secret (as
the `AuthKey`) and then also knowledge of `pin_1` slot before you
can read or write (as `ReadKey` or `WriteKey`). Each of the PIN
slots (1-4) unlocks the next corresponding `secret_N` slot for
read/write of the secret. The `lastgood` slots are world readable,
but need the correspond PIN to change.

Note that all keyslots require the pairing secret to do anything
(ie. it is the `AuthKey` for those slots). The pairing secret itself
is not readable, and can be changed only by the `brickme` PIN. We do
this so that we can trash the secure element by "rolling" the pairing secret to
a new value and then forgetting what that value is. (In fact we
don't calculate the new key value, since we're being destructive.)
It should be noted, that only key rolling is permitted (not general
write), and so you need to know the previous value of the pairing
secret in order to change it.

The 'firmware' key slot holds a hash value, and you must prove
knowledge of that value to be able to turn the Genuine light green.
Anyone can turn the light to red (it is unauthenticated) but you
must know both the pairing secret and the existing value in keyslot
14 to turn the light green. We can capture and store a hash over
the entire flash memory at any time, but update it, knowledge of
the main PIN is needed.

You may confirm the above configuration details as the configuration
zone is not read-protected and it can be read very easily. It can
be done from Micropython level or your could connect directly to
the chip.


## "Knowledge of" Keys

In this document we say you "need knowledge of" a specific key to
be able to do something. What that means in practice, is you have
to complete this sequence:

- pick 20 bytes of nonce (`numin`)
- do a `Nonce` command, which takes that 20 bytes, and returns 32 bytes.
- the 32 bytes you receive are a random value picked by the chip
- take the 20 you provided, and 32 from the chip and hash them together to make a shared nonce value
- take your knowledge of some key you think is in the chip, and hash it with the shared nonce
- do a `CheckMac` command, which sends that MAC to the secure element, if it
  doesn't like the value because it doesn't match the value it calculated itself, then it fails.
- once a `CheckMac` is done, you've proven you know the indicated key slot's value

Every key on the chip has been configured so that the above sequence
must be completed with the pairing secret. After that, most slots
need the same sequence to be repeated with another secret, such as
the user-defined PIN. After two `CheckMac` sequences are done, you
may be able to read or update a specific field. The actual read/write
data may also be encrypted which involves XOR of the data against
a hash generated by a similar sequence of steps, again with a random
nonce involved (using the `GenDig` command).

The fun part of programming this chip is the constant values and
other clever things they mix into the digests required at each step.
A simple update can require a number of back and forthes, each time
creating a new shared nonce. Specific parts of the chip's configuration
zone, and the arguments to the specific command are often included
in the hashes. Of course, every single bit must be correct or nothing
works, and a meaningless error is returned.


## Securely rate-limiting PIN retries

In our system, we do not trust the main firmware with any secrets...
at least until it proves it knows the PIN. To achieve this separation,
the bootloader picks the pairing secret and keeps it secret. We use
a hardware firewall feature of this chip: it monitors the internal
memory bus, and if it sees an address inside the firewall range,
it simply resets the entire chip. That firewall protects the entire
bootloader section from any access from other code running on the chip,
regardless of how that might happen.

The bootloader configures the firewall, and verifies flash-memory
protections when it boots the system. During operation, the main
firmware, written in Micropython, can make calls into the bootloader
to communicate with the secure element, and do a few other functions.
All access to the bootloader's firmware is done indirectly via this
"callgate" which opens the firewall in a very limited way. Entry
and exit from the callgate is handled carefully, and does things
like wipe all the SRAM used by the bootloader with known values
both on entry and exit.

In order for the main UI to test a PIN code, it must use the callgate,
and the calls involved require a fairly complex call sequence:
First, a setup step is needed that loads the retry counter and
establishes how long a delay will be required before we will check
the PIN attempt.  Then the delay must be passed, by another call
through the call gate.  The delay is done inside the bootloader
just so that we know how long it is, and so there is no way to
bypass it. We do this in increments of 500ms because we want to
maintain a nice display and UX during this potentially-long time
period. After the timeout period is completed, we will attempt using
the PIN value, and if it's right, provide the secret.

This sequence is implemented with a data structure that is signed
by an HMAC generated by the bootloader. The HMAC includes both the
pairing secret and also a unique value-per-boot to prevent replays.


### Delay Policy (before Mk3)

Here is the delay you'll be forced into based on the
number of failed PIN attempts, since your last successful login:


| Failures  | Forced Delay Between Attempts
|:---------:|-----------
| 1 ... 2   | 15 seconds
| 3 ... 4   | 1 minute
| 5 ... 9   | 5 minutes
| 10 ... 19 | 30 minutes
| 20 ... 49 | 2 hours
| more      | 8 hours

In Mark 3, no extra delay is enforced, but a warning and confirmation
is shown every 5 attempts so that you don't burn through you limited
attempts too causually.


## Limitation

_(before Mk3)_

The main PIN holder can brute-force the secondary wallet's PIN
because they can use the API for pin-change without rate limiting.
(Some micropython code would need to be written.) Similarly, the
brickme and duress change-pin commands are not rate-limited, so if
you have the main PIN (or secondary) you could brute-force the
corresponding PIN codes.

Mk3 hardware does not have this weakness. There is no way to accelerate
the PIN-attempts, nor to exceed the maximum number of them.


# Changes for Mark 3

With the Mk3 hardware, introduced in 2019, we upgrade to the ATECC608A chip
in place of the 508a as the secure element.

Because of changes to that part, we have the opportunity to 
improve security as follows:

- The limited-use counter is now connected to pin attempts inside the chip (not external).

- The 608a compares the number of PIN attempts, and if too many failures have occured,
  the secure element bricks itself.

- Using a new KDF feature of the chip, we perform multiple HMAC cycles using a secret
  known only to the secure element (and unique per Coldcard). The purpose of this is
  make each PIN attempt slow to perform. The previous delay policy was removed,
  in favour of the delay enforced by the chip itself.

- An addition 416 bytes of secrets storage is enabled (in addition to 72 bytes of storage
  previously stored).

- The secondary wallet feature had to be removed, because there is only one limited-use
  counter.

- Anti-phishing words are calculated in a slightly different manner but with equivilent
  security design.

