
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
