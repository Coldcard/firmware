# Spending Policy

A special mode where your coldcard will stop you from signing transactions if
they exceed a spending policy you define beforehand.

# Tips and Tricks

## Money Manager Mode

You could setup a Coldcard for another person, perhaps a family member,
and enable web 2FA authentication. There does not need to be any
other spending policy limits (velocity could be unlimited).

Then enrol your own phone with the required 2FA values, and
keep both that and the spending policy bypass PIN confidential.

The holder the the Coldcard will need a 2FA code from your phone
when they want to spend. They can call you for the 6-digit code
from the 2FA app on your phone. This is not hard to provide over a
voice call.

Because a spending policy is in effect, they will not be able to
see the seed words, other private key material, so regardless of
any spoofing or phishing, they cannot move funds without your help.

You should record the bypass PIN in a safe way, so it can be revelaed
should you die. You do not need to share the risks associated with
holding a copy of their seed words.

## Lock Out Changes to Policy

You may go into the Trick Pin menu, find the Bypass PIN there.  You
could delete or "hide" it. Hiding it is pointless since you cannot
get to the trick PIN while the policy is in effect. Deleting the
PIN however, is useful because it assures changes to spending policy
are impossible. To recover the COLDCARD when this move is later
regretted, under Advanced, there is "Destroy Seed" option which
will clear the seed words and all settings, including the spending policy.

## Passphrase Considerations

If you are using a BIP-39 passphrase for everything, you should
probably do a "Lock Down Seed" (Advanced/Tools > Danger Zone > Seed
Functions) first. This takes your master seed and bip-39 passphrase
and cooks them together into an XPRV which then is stored as your
master secret (not a seed phrase anymore). This process cannot be
reversed, so other funds you may have on the same seed words are
protected. Once you are operating in XPRV mode, you can define a
spending policy and know that it is restricted to only that wallet.

You can also block access to other related keys, which removes the 
"Passphrase" entry option from the main menu, but that protection
doesn seem as strong.

## Trick PIN Thoughts

When doing your game theory w.r.t to bypass mode and this feature,
remember that you should assume the attacker already has your main
PIN. That's how they know they cannot spend all your coin, because
they either tried to, or noticed the menus are very limited. They also
have all your UTXO locations and total wallet balance (because they
can export xpubs to any wallet and load balance from there).

Therefore, a trick pin that leads to a duress wallet after giving up 
the bypass unlock PIN, will not fool them. Best would be to provide
a false bypass PIN that is in fact a brick/wipe PIN.


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
