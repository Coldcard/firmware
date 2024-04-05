
# MicroSD as a Second Factor for Login

When enabled, this feature requires a specially prepared MicroSD
card to be inserted during login process. After correct PIN is
provided, if card slot is empty or unknown card present, the seed
is wiped.

## How it Works

To "enroll" a card, a small encrypted file is written to the card.

During login, after the correct (true) PIN is entered, we use
the master secret to construct an AES key which is used to decrypt
the file found on the card. If the file is JSON and contains a nonce,
we check that in our list of acceptable cards.

The AES key includes the master secret and also a hash of the
unique serial number of the card, retrieved using low-level 
protocols. This prevents moving the file to another card.

To allow the same card to unlock multiple Coldcards, we write the
file using a filename derived from the serial number of the Coldcard
(hashed). Thus there could be a number of 2FA-enabling files on a
single card.

The file name starts with a dot, and has extension `.2fa`. Your
tools may or may not hide it from you based on Unix filename
conventions. Reformating the card will certainly remove this file,
so keep that in mind when managing your "special" cards.

If using COLDCARD Q and both card slot are populated during login
make sure that enrolled card is in top slot (slot A).

## Menu Settings

See menu in: `Settings -> Login Settings -> MicroSD 2FA`

The option is enabled only once the main secret is picked. It cannot
be used with ephemeral seeds, as that secret will not be in effect
during boot time.

The menu initially contains only "Add Card". Once one or more
cards are enabled (and the feature is activated), additional
options appear: "Check Card" and "Remove Card #N" (for each
enrolled card).

"Check Card" validates the card inserted and indicates if it would 
be accepted or not.

Use "Remove Card #N" is remove cards from the approved list. When
the last card is removed, the feature is disabled and no card will
be required for login. Access to the card in question is not required
to remove it.

## During Login

After the PIN is entered, and if it is the true PIN (or the main
code thinks it is, in Delta Mode or Duress Wallet cases) the main
settings are read. After this point, if there are one or more card
enrolled, then the check is performed. If the slot is empty or
the card fails the check, a fast wipe of the seed is done and shown
on screen. The memory is wipe and system stops. You must power cycle
to continue.

## Tricky Thinking

Because settings are encrypted by the master seed, if you have a
duress wallet, it could have required cards set as well. Generally,
we do not see a good use for this, and assume that typically only
the "true" PIN will have required cards associated with it. Remember
any Trick PIN can wipe the seed directly.

In Delta Mode, the usual card policy is in effect. However, if you
are relying on this 2FA feature to wipe the seed in a case of duress,
there doesn't seem to be any need for Delta Mode.

## Duress Defenses

We recommend simply keeping no card in your Coldcard once activating
this feature. Your attacker, or yourself under duress, will login
normally and trigger this defense without you taking any explicit
action.

If you were being forced to prepare a PSBT under duress, you can
choose which SD card to use (so pick a normal one, which isn't
enrolled) and you may also have a chance to clear your card of the
special file. Either way would be an opportunity to ensure the
automatic wipe occurs, even as you comply and provide the PIN code.

Your enrolled SD cards can also be stored at another location away
from your Coldcard. This could be a bank safety deposit box, since
it contains no sensitive data.

If you are closely surveilled when logging and using your Coldcard,
the PIN code might already be known to your attacker. However, there
is no indication on the screen during a normal (successful) login
that this feature is in effect, so they would not know if the SD
card was inserted by chance or necessity.

