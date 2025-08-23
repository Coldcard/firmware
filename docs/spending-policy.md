# Spending Policy

This special mode will stop you from signing transactions if they
exceed a spending policy you define beforehand. Once enabled, many
features of the COLDCARD are disabled or inaccessible.

You might want to use this feature when traveling with your COLDCARD.

## Spending Policy: Multisig (formerly CCC)

We also support a mode where the COLDCARD is a multisig co-signer
and only performs its signature when a spending policy is met. The
other multisig signers are free to sign or not sign as appropriate.

Multisig mode is more advanced and requires use of multisig addresses,
new UTXO, and cooperating multisig on-chain wallets.

This document will only discuss the "Single signer" version of
Spending Policy. Both modes can be active at the same time, but if
a transaction would be signed by Multisig policy, then we assume
it's also okay to sign your main key as well.

# Before You Start

When a Spending Policy is in effect, there are limitations
in effect:

- Firmware updates are blocked.
- There is no way to backup the COLDCARD
- Seed vault and Secure Notes are read-only (and can also be hidden).
- Settings menu is inaccessible.

We recommend getting the COLDCARD fully configured and setup
for typical transactions before enabling the Spending Policy.

# Setup Spending Policy

Visit `Advanced / Tool > Spending Policy" menu and choose
"Single-Signer". First some background information is shown,
then you are prompted to define the "Bypass PIN". This PIN code
is only used when you need to disable the spending policy, but is 
also the only way to do so once enabled... so don't loose it.

Once the "Bypass PIN" is confirmed, you will arrive at menu for
related settings. Use "Edit Policy..." to change the spending policy
and define a Max Magnitude (limit number of BTC per transaction),
Velocity (minimum time gaps between signed transactions). You can
define a whitelist of up to 25 destination addresses (leave empty
for any). Finally you can enroll your phone in 2FA (second factor)
so that you must open an Authenticator app on your phone before
transactions are signed.

## Other Security Settings

In addition to policy itself, there are a number of on/off
switches which affect operation of the COLDCARD while the Spending
Policy is in effect:

### Word Check

If enabled, you will have to enter the first and last seed word
after the Bypass PIN as an additional security check.

### Allow Notes

On the Q, secure notes and passwords may be visible or hidden
using this setting. In either case they are strictly readonly.

### Related Keys

BIP-39 passphrase entry, Seed Vault usage can be blocked with
this setting. Even when enabled, the Seed Vault is always readonly.

# Other Menu Items

## Last Violation

If you have recently tried and failed to sign a transaction, the
reason for the transaction being rejected can be viewed and cleared,
using menu item "Last Violation". It is shown only if a Spending
Policy violation (attempt) has occurred since the last valid signing.

This is meant as a debugging tool, and the information stored is
terse.

## Remove Policy

This will remove your spending policy completely and remove
the Bypass PIN. Your COLDCARD will be back to normal.

## Test Drive

Experiment with how the COLDCARD will function if the Spending
Policy was enabled. You can try to sign transactions that should
be rejected and view the menus in the new mode without rebooting.

Choose "EXIT TEST DRIVE" on top menu to return to the Spending
Policy menu. Reboot will also restore normal operation without
any special challenges.

## ACTIVATE

This step will enable the Spending Policy and return to the
main menu with it in effect. When you reboot the COLDCARD,
the policy will still be in effect. You must use the
Bypass PIN, followed by the normal main PIN, possibly
followed by entering the first and last words of your seed
phrase, before you can disable and change the policy.

We recommend test-driving the feature before doing that.


# Tips and Tricks

## Money Manager Mode

You could setup a Coldcard for another person, perhaps a family member,
and enable web 2FA authentication. There does not need to be any
other spending policy limits (velocity could be unlimited).

Then enroll your own phone with the required 2FA values, and
keep both that and the spending policy bypass PIN confidential.

The holder the the Coldcard will need a 2FA code from your phone
when they want to spend. They can call you for the 6-digit code
from the 2FA app on your phone. This is not hard to provide over a
voice call.

Because a spending policy is in effect, they will not be able to
see the seed words, other private key material, so regardless of
any spoofing or phishing, they cannot move funds without your help.

You should record the bypass PIN, so it can be revealed somehow,
should you die. You do not need to share the risks associated with
holding a copy of the seed words.

## Passphrase Considerations

If you are using a BIP-39 passphrase for everything, you should
probably do a "Lock Down Seed" (Advanced/Tools > Danger Zone > Seed
Functions) first. This takes your master seed and BIP-39 passphrase
and cooks them together into an XPRV which then is stored as your
master secret. (It is not a seed phrase anymore.) This process
cannot be reversed, so other funds you may have on the same seed
words are protected. Once you are operating in XPRV mode, you can
define a spending policy and know that it is restricted to only
that wallet.

You could, alternatively, can also block access to other related
keys, which removes the "Passphrase" entry option from the main
menu, but that protection doesn't seem as strong. When operating in
XPRV mode, the "Passphrase" menu item is not shown because
BIP-39 passwords cannot be applied to XPRV secrets.

## Trick PIN Thoughts

When doing your game theory w.r.t to bypass mode and this feature,
remember that you should assume the attacker already has your main
PIN. That's how they know they cannot spend all your coin, because
they either tried to, or noticed the menus are very limited. They also
have all your UTXO locations and total wallet balance (because they
can export your xpubs to any wallet and load balance from there).

Therefore, a trick pin that leads to a duress wallet after giving up 
the bypass unlock PIN, will not fool them. Best would be to provide
a false bypass PIN that is in fact a brick/wipe PIN.


## Lock Out Changes to Policy

In the Trick Pin menu once Spending Policy has been enabled, you will
find the Bypass PIN listed.  You could delete or "hide" it. Hiding
it is pointless since you cannot get to the trick PIN menu while
the policy is in effect. Deleting the PIN however, is useful because
it assures changes to spending policy are impossible. To recover
the COLDCARD when this move is later regretted, under Advanced,
there is "Destroy Seed" option which will clear the seed words and
all settings, including the spending policy.

### Unlock Policy & Wipe

We've provided a new trick PIN that pretends to be the unlock
spending policy pin, so the login sequence is correct... but it
will wipe the seed in the process. It will be obvious to your
attackers that you've wiped the seed because the main PIN will lead
to blank wallet now (no seed loaded).

### Delta Mode and Spending Policy

If, from the start, you gave your "delta mode PIN" to the attackers,
then when they bypass the policy (after also getting the bypass PIN
from you), they will still be in Delta Mode.

They could attempt unlimited spending, but transactions signed will
not be valid. If they try to view the seed words or generally export
private key material, they will hit many of the "wipe seed if delta
mode" cases.
