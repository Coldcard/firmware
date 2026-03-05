# Change Log

This lists the changes in the most recent firmware, for each hardware platform.

# Shared Improvements - Both Mk and Q

- New Feature: Sign [BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) Proof of Reserve PSBT files.
    - Requires a carefully crafted PSBT that does not represent a monetary transaction, but instead is demonstrating
      control over the keys for a list of UTXO, and commits to a short text message.
    - Read more [here](https://github.com/Coldcard/firmware/blob/master/docs/proof-of-reserves-bip-322.md).
- New Feature: WIF Store. Ability to import foreign WIF keys (Wallet Import Format) and use them for PSBT signing.
- New Feature: Export [BIP-380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki) extended key expression.
  Navigate to "Advanced/Tools -> Export Wallet -> Key Expression"
- New Feature: Transaction Input Explorer. Shows data about UTXO(s) being spent. Press (2) before approving 
  transaction to enter Transaction Explorer.
- New Feature: Support for v3 transactions in PSBT files.
- New Feature: Option to type a derived BIP-85 secret as an emulated USB keyboard.
- New Feature: Nuke Device: purges all sensitive data and makes your COLDCARD e-waste.
- Enhancement: CCC debug menu allows you to reset block height.
- Enhancement: Show the BIP-39 passphrase on-screen (must scroll down) once new key is in effect.
- Enhancement: New "Buried Settings" menu, inside Settings menu, for rarely-applied settings.
- Enhancement: Add "Blue Wallet" option to "Export Wallet"
- Enhancement: Detect duplicated inputs in PSBT file.
- Bugfix: Replace `/` with `-` in exported file names of multisig wallet export artifacts.

# Mk Specific Changes

## 5.5.0 - 2065-03-05

- Enhancement: Show QR of XOR-split seeds.


# Q Specific Changes

## 1.4.0Q - 2065-03-05

- Bugfix: Empty notes in hobbled mode caused yikes upon menu entry.



# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk4.md`](History-Mk4.md)
- [`History-Mk3.md`](History-Mk3.md)

