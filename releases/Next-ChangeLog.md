# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk and Q

- New Feature: Export [BIP-380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki) extended key expression.
  Navigate to `Advanced/Tools -> Export Wallet -> Key Expression`
- New Feature: Transaction Input Explorer. Shows data about UTXO(s) being spent. Press (2) before approving 
  transaction to enter Transaction Explorer.
- New Feature: Support for v3 transactions in PSBT files.
- New Feature: Option to type-out derived BIP-85 secrets as a USB keyboard.
- New Feature: Nuke Device, purges all sesnsitive data and make COLCARD into e-waste.
- Enhancement: CCC debug menu allows your to reset block height.
- Bugfix: Replace `/` with `-` in exported file names of multisig wallet export artifacts.
- Enhancement: Show the BIP-39 passphrase on-screen (must scroll down) once new key is in effect.
- Enhancement: New "Buried Settings" menu, inside Settings menu, for rarely-applied settings.
- Enhancement: Add `Blue Wallet` option to `Export Wallet`

# Mk Specific Changes

## 5.4.5 - 2025-12-xx

- Enhancement: Show QR of XOR-split seeds.


# Q Specific Changes

## 1.3.6Q - 2025-12-xx

- Bugfix: Empty notes in hobbled mode caused yikes upon menu entry.


