# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk4 and Q

- New Feature: Opt-in support for `multi(...)` - unsorted multisig. Enable here `Settings->Multisig Wallets->Legacy Multisig`
- New Feature: Named multisig descriptor imports. Wrap descriptor in json {"name:"ms0", "desc":"<descriptor>"} with name key 
  to use this name instead of the filename. Mostly usefull for USB and NFC imports that have no file, 
  in which case name was created from descriptor checksum.
- Enhancement: Allow JSON files in `NFC File Share`
- Enhancement: latest [0.5.0](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.5.0) libsecp256k1
- Enhancement: Signature grinding optimizations.
- Enhancement: Improve side-channel protection: libsecp256k1 context randomization now happens
  before each signing session.
- Change: Do NOT require descriptor checksum when importing multisig wallets
- Bugfix: Do not alow to import multisig wallet duplicate with only keys shuffled.
- Bugfix: Do not read whole PSBT into memory when writing finalized transaction.
- Bugfix: Properly handle null data in `OP_RETURN`.
- Bugfix: Prevent user from restoring Seed XOR when len parts is smaller than 2.
- Bugfix: Fix display alignment of Seed Vault menu.
- Change: Remove Lamp Test from Debug Options (lights covered by selftest)

# Mk4 Specific Changes

## 5.3.4 - 2024-08-xx

- tbd


# Q Specific Changes

## 1.2.4Q - 2024-08-xx

- New Feature: Seed XOR can be imported from SeedQR scanned.
- New Feature: Input backup password from QR scan.
- New Feature: (BB)QR file share of arbitrary files.
- Bugfix: Properly clear LCD screen after BBQR is shown.
- Bugfix: Writing to empty slot B caused broken card reader.
- Bugfix: During Seed XOR import, display correct letter B if own seed already added to the mix.


