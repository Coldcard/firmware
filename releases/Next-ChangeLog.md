# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk4 and Q

- New Feature: Opt-in support for unsorted multisig, which ignores BIP-67 policy. Use
  descriptor with `multi(...)`. Disabled by default, Enable in 
  `Settings > Multisig Wallets > Legacy Multisig`. Recommended for existing multisig
  wallets, not new ones.
- New Feature: Named multisig descriptor imports. Wrap descriptor in json:
    `{"name:"ms0", "desc":"<descriptor>"}` to provide a name for the menu in `name`.
  instead of the filename. Most useful for USB and NFC imports which have no filename, 
  (name is created from descriptor checksum in those cases).
- New Feature: XOR from Seed Vault (select other parts of the XOR from seeds in the vault).
- Enhancement: upgrade to latest 
  [libsecp256k1: 0.5.0](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.5.0) 
- Enhancement: Signature grinding optimizations. Now faster!
- Enhancement: Improve side-channel protection: libsecp256k1 context randomization now happens
  before each signing session.
- Enhancement: Allow JSON files in `NFC File Share`.
- Change: Do not require descriptor checksum when importing multisig wallets.
- Bugfix: Do not allow import of multisig wallet when same keys are shuffled.
- Bugfix: Do not read whole PSBT into memory when writing finalized transaction (performance).
- Bugfix: Prevent user from restoring Seed XOR when number of parts is smaller than 2.
- Bugfix: Fix display alignment of Seed Vault menu.
- Bugfix: Properly handle null data in `OP_RETURN`.
- Bugfix: Do not allow lateral scroll in Address Explorer when showing single address
  from custom path.
- Change: Remove Lamp Test from Debug Options (covered by selftest).

# Mk4 Specific Changes

## 5.4.0 - 2024-09-12

- Shared enhancements and fixes listed above.


# Q Specific Changes

## 1.3.0Q - 2024-09-12

- New Feature: Seed XOR can be imported by scanning SeedQR parts.
- New Feature: Input backup password from QR scan.
- New Feature: (BB)QR file share of arbitrary files.
- New Feature: `Create Airgapped` now works with BBQRs.
- Change: Default brightness (on battery) adjusted from 80% to 95%.
- Bugfix: Properly clear LCD screen after BBQR is shown.
- Bugfix: Writing to empty slot B caused broken card reader.
- Bugfix: During Seed XOR import, display correct letter B if own seed already added to the mix.
- Bugfix: Stop re-wording UX stories using a regular expression.
- Bugfix: Fixed "easy exit" from quiz after split Seed XOR.


