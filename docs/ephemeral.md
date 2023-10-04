# Ephemeral Seeds

Ephemeral seed is temporary secret mostly stored only in Coldcard volatile
memory (RAM). Ephemeral seed can also be stored in `Seed Vault` (5.2.0+). 
It only survives single boot, meaning after Coldcard
restart it is gone. Ephemeral seeds *completely* defeats the design
of Coldcard's security model, based on secure elements.

Make sure you know what you're doing!


## Usage

- go to `Advanced/Tools -> Ephemeral Seed`
- if ephemeral seed is already in use, top menu item `[<xfp>]` is visible
  with fingerprint of ephemeral master secret
- an ephemeral seed can be Imported or Generated at random
- go to `Advanced/Tools -> Ephemeral Seed`
- `Generate Words`:
  - same options as generating new seed words, dice rolls included
  - Import words via NFC with `Import via NFC` option
- `Import Words`:
  - same options as importing seed words
- `Import XPRV`:
  - import extended private key
- `Tapsigner Backup`
  - import TAPSIGNER encrypted backup
- an ephemeral seed can also be a BIP-85 derived value

## Trick PIN Notes

If you intend to use the ephemeral seed feature frequently, you can
define a "Trick PIN" which takes you to a "look blank" trick wallet
(ie.  no seed set appears to be set).  Then you may then safely
unlock your Coldcard, without revealing the true PIN, and perform
all your ephemeral seed work in that state.

## Purpose

This feature is intended for those one-off signings, like recovering
a lost seed from some other system or importing some seed as an
balance check. We do not recommend handing unencrypted seed material
on a regular basis!

