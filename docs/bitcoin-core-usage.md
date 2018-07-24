# Using Coldcard with Bitcoin Core

## Background

Core has not always supported BIP32 hierarchical keys, and it does not presently
support BIP44 derivation. Instead it uses derivation like this:

    m/0'/{change}'/{index}'

It will also, as of 0.16, do Segwit in P2SH by default. In time, `bech32` will
become the default address format.

## Setup Steps

- generate a new seed phrase on the Coldcard
- export the xpub file from Coldcard (USB or MicroSD)
- import that xpub as a new wallet in core
- display balances

## Day-to-day Operation

- generate unsigned transactions
- get that onto the Coldcard, and sign it there
- use core to broadcast the new txn for confirmation

## Use of "dumpwallet" command

- You can do a "dumpwallet" command and get the `xprv` associated with your
wallet. We can import that, and then you'd need to destroy the existing wallet
files, backups of those, and so on.

- Our output file, called `public.txt`, can be compared to dumpwallet's output, but:
    - you must find the section with appropriate derivation path for core
    - core puts the addresses into a random order, not sequential like ours
    - segwit, and p2sh segwit choice has to match


