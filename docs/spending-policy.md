
# Spending Policy

A special mode where your coldcard will stop you from signing transactions if
they exceed a spending policy you define beforehand.



## Tips and Tricks

If you are using a BIP-39 passphrase for everything, you should
probably do a "Lock Down Seed" (Advanced/Tools > Danger Zone > Seed
Functions) first. This takes your master seed and bip-39 passphrase
and cooks them together into an XPRV which then is stored as your
master secret (not a seed phrase anymore). This process cannot be
reversed, so other funds you may have on the same seed words are
protected. Once you are operating in XPRV mode, you can define a
spending policy and know that it is restricted to only that wallet.

## Trick PIN Thoughts

When doing your game theory w.r.t to bypass mode and this feature,
remember that you should assume the attacker already has your main
PIN. That's how they know they cannot spend all your coin, because
they either tried to, or noticed the menus are very limited. They also
have all your UTXO locations and total wallet balance (because they
can export xpubs to any wallet and load balance from there).

Therefore, a trick pin that leads to a duress wallet after giving up 
the bypass unlock PIN does not fool them. Best would be to provide
a false bypass PIN that is in fact a wipe PIN.

### Unlock Policy & Wipe

We've provided a new trick PIN that pretends to be the unlock
spending policy pin, so the login sequence is correct... but it
will wipe the seed in the process. It will be obvious to your
attackers that you've wiped the seed because the main PIN will lead
to blank wallet now (no seed loaded).

### Delta Mode and Spending Policy

If, from the start, you gave your "delta mode PIN" to the attackers,
then when they bypass the policy (after also getting the bypass PIN from you),
they will still be in Delta Mode.

They could attempt unlimited spending, but transactions signed will
not be valid. If they try to view the seed words or generally export
private key material, they may hit many of the "wipe seed if delta mode"
cases.
