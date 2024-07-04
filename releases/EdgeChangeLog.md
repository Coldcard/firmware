# Change Log

## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.  DO NOT use for large Bitcoin amounts.
```

This lists the changes in the most recent EDGE firmware, for each hardware platform.

# Shared Improvements - Both Mk4 and Q

- New Feature: Ranged provably unspendable keys and `unspend(` support for Taproot descriptors
- New Feature: Address ownership for miniscript and tapscript wallets
- Enhancement: Address explorer simplified UI for tapscript addresses
- Bugfix: Constant `AFC_BECH32M` incorrectly set `AFC_WRAPPED` and `AFC_BECH32`.
- Bugfix: Trying to set custom URL for NFC push transaction caused yikes


# Mk4 Specific Changes

## 5.3.3X - 2024-07-04

- Bugfix: Fix yikes displaying BIP-85 WIF when both NFC and VDisk are OFF
- Bugfix: Fix inability to export change addresses when both NFC and Vdisk id OFF
- Bugfix: In BIP-39 words menu, show space character rather than Nokia-style placeholder
  which could be confused for an underscore.


# Q Specific Changes

## 1.2.3QX - 2024-07-04

- Enhancement: Miniscript and (BB)Qr codes
- Bugfix: Properly clear LCD screen after simple QR code is shown



# Release History

- [`History-Edge.md`](History-Edge.md)
